package burp;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
//import org.apache.commons.lang.StringEscapeUtils;


public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private int counter = 0;
    private String nextToken = "";

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("UpdateToken");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
    }


    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {
        boolean updated = false;

        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            burp.IHttpService httpService = messageInfo.getHttpService();
            burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

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
        else//it's a response - grab a new token
        {
            burp.IRequestInfo iResponse = helpers.analyzeRequest(messageInfo);
            String response = new String(messageInfo.getResponse());


            //start at {"access_token":"
            //end at "
            if (response.contains("{\"access_token\":\"")) {
                //get next csrf token
                String startMatch = "{\"access_token\":\"";
                String endMatch = "\"";
                int tokenStartIndex = response.indexOf(startMatch) + startMatch.length();
                int tokenEndIndex = response.indexOf(endMatch, tokenStartIndex+1);
                stdout.println("tokenStartIndex: " + tokenStartIndex);
                stdout.println("tokenEndIndex: " + tokenEndIndex);
                nextToken = response.substring(tokenStartIndex, tokenEndIndex);
                stdout.println("grabbed token: " + nextToken);

            }
        }
    }
}
