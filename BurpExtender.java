package burp;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
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
        updating = false; // cheat flag so it doesn't inf loop
        
        // set our extension name
        cb.setExtensionName("OauthRefresher");

        // register ourselves as a HTTP listener
        cb.registerHttpListener(this);
        
        // add a new tab 
        gui = new ExtenderUI();
        cb.customizeUiComponent(gui);
        cb.addSuiteTab(gui);
    }
    
    /* https://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
     * straight copy/paste from link above
     */
    private Map<String, String> splitQuery (String query) throws UnsupportedEncodingException  {
    Map<String, String> query_pairs = new LinkedHashMap<String, String>();
    String[] pairs = query.split("&");
    for (String pair : pairs) {
        int idx = pair.indexOf("=");
        query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
    }
    return query_pairs;
}
    
    // refactored to a function, updates global variable for token and expiry
    // could refactor again to use regex... makes it a bit shorter
    private void setToken(String response) {
        String res = response.replace(" ", ""); // get rid of extra spaces
        if (res.contains("\"" + gui.getExpiryPattern() + "\":\"")) {
            String startMatch = "\"" + gui.getExpiryPattern() + "\":\"";
            String endMatch = "\"";
            int tokenStartIndex = res.indexOf(startMatch) + startMatch.length();
            int tokenEndIndex = res.indexOf(endMatch, tokenStartIndex+1);
            
            if (gui.getExpiryMode() == "Seconds") {
                
                try {
                    expiry = LocalDateTime.now().plusSeconds(Integer.parseInt(res.substring(tokenStartIndex, tokenEndIndex)));
                    stdout.println("Grabbed expiry time: " + expiry);
                } catch (Exception e) {
                    stdout.println("Seems like expiry wasn't an integer, here's some debug:");
                    stdout.println(e);
                }
            } else if (gui.getExpiryMode() == "Epoch") {
                try {
                    expiry = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.parseLong(res.substring(tokenStartIndex, tokenEndIndex))),
                            ZoneId.systemDefault());
                    stdout.println("Grabbed expiry time: " + expiry);
                } catch (Exception e) {
                    stdout.println("Seems like expiry wasn't in epoch time, here's some debug:");
                    stdout.println(e);
                }
            } else if (gui.getExpiryMode() == "CustomSeconds") {
                
                try {
                    expiry = LocalDateTime.now().plusSeconds(Integer.parseInt(gui.getCustomExpiry()));
                    stdout.println("Grabbed expiry time: " + expiry);
                } catch (Exception e) {
                    stdout.println("Seems like expiry wasn't an integer, here's some debug:");
                    stdout.println(e);
                }
            }
        } else {
            expiry = LocalDateTime.now();
        }
        if (res.contains("\"" + gui.getTokenPattern() + "\":\"")) {
            String startMatch = "\"" + gui.getTokenPattern() + "\":\"";
            String endMatch = "\"";
            int tokenStartIndex = res.indexOf(startMatch) + startMatch.length(); 
            int tokenEndIndex = res.indexOf(endMatch, tokenStartIndex+1);
            nextToken = res.substring(tokenStartIndex, tokenEndIndex);
            stdout.println("Grabbed oauth token: " + nextToken);
            gui.addToTable(scope, nextToken, expiry);
        }
    }
    
    private void updateHeader(List<String> headers) {
        // Code for updating a token in a Header
        // log old header & update new header
        for (int i = 0; i < headers.size(); i++) {
            String H = headers.get(i);
            String oauthToken = "";
            
            if (H.contains("Authorization: Bearer")) {
                oauthToken = H.split(" ")[2];
                stdout.println("\nAuthorization header used to be: " + oauthToken);
                H = "Authorization: Bearer " + gui.getToken();
                stdout.println("Authorization header until " + gui.getExpiry() + ": " + gui.getToken());
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
            if (helpers.analyzeRequest(messageInfo).getUrl().toString().contains(gui.getURLPattern())) {
                oauthRequest = helpers.buildHttpMessage(headers, reqBody.getBytes());
                stdout.println("Saving oauth token request: \n" + helpers.bytesToString(oauthRequest) + "\n");
                String auth = "";
                // check for basic auth or some other auth method
                for (String s : headers) {
                    if (s.contains("Authorization")) {
                        auth = s.split(":")[1];
                    }
                }
                gui.addTokenCall(helpers.analyzeRequest(messageInfo).getUrl().toString(), httpmethod, auth, reqBody, LocalDateTime.now());
                try {
                    scope = splitQuery(reqBody).get("scope");
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
            // little check to see it actually has an Authorization header
            boolean authFlag = false;
            for (String s : headers) {
                if (s.contains("Authorization")) {
                    authFlag = true;
                }
            }
            
            // Update Token Logic
            if (gui.getRowCount() > 0 && gui.getExpiry() != null && authFlag &&
                    LocalDateTime.now().isAfter(LocalDateTime.parse(gui.getExpiry())) && !updating) {
                // don't need the response, it comes back to processHttpMessage
                // and goes to the response section
                stdout.println("Expired Token (" + nextToken + "), getting a new one");
                updating = true;
                try {
                    cb.makeHttpRequest(httpService, oauthRequest);
                    updated = true;
                    updateHeader(headers); 
                } catch (Exception e) {
                    stdout.println("No Oauth Request saved!");
                }
            } else if (!nextToken.equals("")) { 
                updated = true;
                updateHeader(headers);
            }

            if (updated) {
                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);
                updating = false;
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