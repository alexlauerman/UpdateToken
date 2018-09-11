package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * base from https://github.com/alexlauerman/UpdateToken/blob/master/src/burp/BurpExtender.java
 */

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks cb;
    private ExtenderUI gui;
    private boolean updating;

    private String nextToken = "";
    private LocalDateTime expiry = null;
    private byte[] oauthRequest = null;
    private String scope = "";

    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        cb = callbacks;
        updating = false;
        
        // set our extension name
        cb.setExtensionName("OauthHelper");

        // register ourselves as a HTTP listener
        cb.registerHttpListener(this);
        
        // add a new tab 
        gui = new ExtenderUI();
        cb.customizeUiComponent(gui);
        cb.addSuiteTab(gui);
    }
    
    // https://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
    public static Map<String, String> splitQuery (String query) throws UnsupportedEncodingException  {
    Map<String, String> query_pairs = new LinkedHashMap<String, String>();
    String[] pairs = query.split("&");
    for (String pair : pairs) {
        int idx = pair.indexOf("=");
        query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
    }
    return query_pairs;
}
    
    // refactored to a function, updates global variable for token and expiry
    private void setToken(String response) {
        if (response.contains("{\"access_token\":\"")) {
            String startMatch = "{\"access_token\":\"";
            String endMatch = "\"";
            int tokenStartIndex = response.indexOf(startMatch) + startMatch.length();
            int tokenEndIndex = response.indexOf(endMatch, tokenStartIndex+1);
            nextToken = response.substring(tokenStartIndex, tokenEndIndex);
            stdout.println("Grabbed oauth token: " + nextToken);
        }

        if (response.contains("\"expires_in\":\"")) {
            String startMatch = "\"expires_in\":\"";
            String endMatch = "\"";
            int tokenStartIndex = response.indexOf(startMatch) + startMatch.length();
            int tokenEndIndex = response.indexOf(endMatch, tokenStartIndex+1);
            try {
                expiry = LocalDateTime.now().plusSeconds(Integer.parseInt(response.substring(tokenStartIndex, tokenEndIndex)));
                stdout.println("Grabbed expiry time: " + expiry);
            } catch (Exception e) {
                stdout.println("Seems like expiry wasn't an integer, here's some debug:");
                stdout.println(e);
            }
            // this part is a bit dodgy..
            gui.addToTable(scope, nextToken, expiry);
            scope = "";
        }
        
    }
    
    private void updateHeader(List<String> headers) {
        // Code for updating a token in a Header
        // log old header & update new header
        for (int i = 0; i < headers.size(); i++)
        {
            String H = headers.get(i);
            String oauthToken = "";

            if (H.contains("Authorization:")) {
                oauthToken = H.split(" ")[2];
                stdout.println("Authorization header used to be: " + oauthToken);
                H = "Authorization: Bearer " + nextToken;
                stdout.println("Authorization header until " + expiry.toString() + ": " + nextToken);
            }
            headers.set(i, H);

        }
    }

    // implement IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        boolean updated = false;

        // only process requests
        if (messageIsRequest) {
            IHttpService httpService = messageInfo.getHttpService();
            IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);
            String request = new String(messageInfo.getRequest());
            List<String> headers = iRequest.getHeaders();
            String reqBody = request.substring(iRequest.getBodyOffset());
            String httpmethod = headers.get(0).split(" ")[0];
           
            // save last oauth request to send through later if token is expired
            if (helpers.analyzeRequest(messageInfo).getUrl().toString().contains("auth/token")) {
                oauthRequest = helpers.buildHttpMessage(headers, reqBody.getBytes());
                stdout.println("Saving oauth token request: \n" + helpers.bytesToString(oauthRequest) + "\n");
                gui.addTokenCall(helpers.analyzeRequest(messageInfo).getUrl().toString(), httpmethod, reqBody, LocalDateTime.now());
                try {
                    scope = splitQuery(reqBody).get("scope");
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                }
                stdout.println("test");
            }
            
            // Update Token Logic
            if (expiry != null && LocalDateTime.now().isAfter(expiry) && !updating) {
                // don't need the response, it comes back to processHttpMessage
                // and goes to the response section
                updating = true;
                cb.makeHttpRequest(httpService, oauthRequest);
                updated = true;
                updateHeader(headers); 
            } else if (!nextToken.equals("")) { 
                updated = true;
                updateHeader(headers);
            }

            if (updated) {
                //stdout.println("-----Request Before Plugin Update-------");
                //stdout.println(helpers.bytesToString(messageInfo.getRequest()).);
                //stdout.println("-----end output-------");

                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);
                updating = false;

                //stdout.println("-----Request After Plugin Update-------");
                //stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                //stdout.println("-----end output-------");
            }
        }
        // it's a response - grab a new token
        else {
            String response = new String(messageInfo.getResponse());
            
            setToken(response);
        }
    }
    
    // implement the tab name
    @Override
    public String getTabCaption() {
        return gui.getName();
    }

    @Override
    public Component getUiComponent() {
        return gui;
    }
}