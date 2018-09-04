/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * base from https://github.com/alexlauerman/UpdateToken/blob/master/src/burp/BurpExtender.java
 * 
 * @author teekayz
 */
public class BurpExtender implements IBurpExtender, IHttpListener, ITab
{
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private int counter = 0;
    private String nextToken = "";

    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // set our extension name
        callbacks.setExtensionName("OauthHelper");

        // register ourselves as a HTTP listener
        callbacks.registerHttpListener(this);
    }


    // implement IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        boolean updated = false;
        LocalDateTime expiry = LocalDateTime.now();

        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            IHttpService httpService = messageInfo.getHttpService();
            IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());

            List<String> headers = iRequest.getHeaders();
            // get the request body
            String reqBody = request.substring(iRequest.getBodyOffset());


            String uri = "";
            String httpmethod = "";
            String hash = "";


            //Get all the data needed
            httpmethod = headers.get(0).split(" ")[0];
            uri = headers.get(0).split(" ")[1];


            //Update Token Logic
            if (!nextToken.equals("")) {

                //Code for updating a token in a Header
                //log old header & update new header
                for (int i = 0; i < headers.size(); i++)
                {
                    String H = headers.get(i);

                    if (H.contains("Authorization:")) {
                        hash = H.split(" ")[2];
                        stdout.println("Authorization header used to be: " + hash);
                        H = "Authorization: Bearer " + nextToken;
                    }

                    headers.set(i, H);
                    updated = true;
                }

                //helpers.updateParameter should work here, but you can't update the iParmaeter using helpers

                //logic for upating token in the body...
                /*String startMatch = "Authorization: Bearer ";
                String endMatch = "\n";
                if (reqBody.contains(startMatch)) {
                    //update csrf token
                    int tokenStartIndex = reqBody.indexOf(startMatch) + 4 + startMatch.length();
                    int tokenEndIndex = reqBody.indexOf(endMatch, tokenStartIndex) - 2;
                    //nextToken = request.substring(tokenIndex+3, tokenIndex+73);
                    reqBody = reqBody.substring(0, tokenStartIndex) + nextToken + reqBody.substring(tokenEndIndex);
                    //stdout.println("updated token: " + nextToken);
                    updated = true;
                }*/
            }

            if (updated) {
                stdout.println("-----Request Before Plugin Update-------");
                stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                stdout.println("-----end output-------");

                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);

                stdout.println("-----Request After Plugin Update-------");
                stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                stdout.println("-----end output-------");
            }
        }
        // it's a response - grab a new token
        else 
        {
            IRequestInfo iResponse = helpers.analyzeRequest(messageInfo);
            String response = new String(messageInfo.getResponse());

            if (response.contains("{\"access_token\":\"")) {
                //get next csrf token
                String startMatch = "{\"access_token\":\"";
                String endMatch = "\"";
                int tokenStartIndex = response.indexOf(startMatch) + startMatch.length();
                int tokenEndIndex = response.indexOf(endMatch, tokenStartIndex+1);
                nextToken = response.substring(tokenStartIndex, tokenEndIndex);
                stdout.println("grabbed oauth token: " + nextToken);

            }
            
            if (response.contains("\"expires_in\":\"")) {
                //get next csrf token
                String startMatch = "\"expires_in\":\"";
                String endMatch = "\"";
                int tokenStartIndex = response.indexOf(startMatch) + startMatch.length();
                int tokenEndIndex = response.indexOf(endMatch, tokenStartIndex+1);
                try {
                    expiry = LocalDateTime.now().plusSeconds(Integer.parseInt(response.substring(tokenStartIndex, tokenEndIndex)));
                    stdout.println("grabbed expiry time: " + expiry);
                } catch (Exception e) {
                    stdout.println("Seems like expiry wasn't an integer");
                    stdout.println(e);
                }
            }
        }
    }
    
    // implement the tab name
    
    @Override
    public String getTabCaption() {
        return "OauthHelper";
    }

    @Override
    public Component getUiComponent() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}