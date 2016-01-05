/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.authenticator.mepin;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLEncoder;

public class MepinTransactions {

    private static Log log = LogFactory.getLog(MepinTransactions.class);

    protected String createTransaction(String mepinID, String sessionID, String url,
                                       String username, String password, String clientId,
                                       String header, String message, String shortMessage,
                                       String confirmationPolicy, String callbackUrl,
                                       String expiryTime) throws IOException {

        log.debug("Started handling transaction creation");

        String query = String.format(MepinConstants.MEPIN_QUERY,
                                     URLEncoder.encode(sessionID, MepinConstants.CHARSET),
                                     URLEncoder.encode(shortMessage, MepinConstants.CHARSET),
                                     URLEncoder.encode(header, MepinConstants.CHARSET),
                                     URLEncoder.encode(message, MepinConstants.CHARSET),
                                     URLEncoder.encode(clientId, MepinConstants.CHARSET),
                                     URLEncoder.encode(mepinID, MepinConstants.CHARSET),
                                     URLEncoder.encode(expiryTime, MepinConstants.CHARSET),
                                     URLEncoder.encode(callbackUrl, MepinConstants.CHARSET),
                                     URLEncoder.encode(confirmationPolicy, MepinConstants.CHARSET)
        );

        String response = postRequest(url, query, username, password);
        if (log.isDebugEnabled()) {
            log.debug("MePin JSON Response: " + response);
        }
        return response;
    }

    private String postRequest(String url, String query, String username, String password)
            throws IOException {

        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));
        String responseString = "";
        HttpsURLConnection connection = null;
        BufferedReader br;
        StringBuilder sb;
        String line;

        try {
            connection = (HttpsURLConnection) new URL(url).openConnection();
            connection.setDoOutput(true);
            connection.setRequestProperty(MepinConstants.HTTP_ACCEPT_CHARSET, MepinConstants.CHARSET);
            connection.setRequestProperty(MepinConstants.HTTP_CONTENT_TYPE, MepinConstants.HTTP_POST_CONTENT_TYPE);
            connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION, MepinConstants.HTTP_AUTHORIZATION_BASIC + encoding);

            OutputStream output = connection.getOutputStream();
            output.write(query.getBytes(MepinConstants.CHARSET));

            int status = connection.getResponseCode();

            if (log.isDebugEnabled()) {
                log.debug("MePIN Response Code :" + status);
            }
            switch (status) {
                case 200:
                    br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    sb = new StringBuilder();
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    br.close();
                    responseString = sb.toString();
                    break;
                case 201:
                case 400:
                case 403:
                case 404:
                case 500:
                    br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    sb = new StringBuilder();
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    br.close();
                    responseString = sb.toString();
                    if (log.isDebugEnabled()) {
                        log.debug("MePIN Response :" + responseString);
                    }
                    return MepinConstants.FAILED;
            }
        } catch (IOException e) {
            if (connection.getErrorStream() != null) {
                br = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
                sb = new StringBuilder();
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                responseString = sb.toString();
                if (log.isDebugEnabled()) {
                    log.debug("MePIN Response :" + responseString);
                }
                return MepinConstants.FAILED;
            }
        } finally {
            connection.disconnect();
        }
        if (log.isDebugEnabled()) {
            log.debug("MePIN Response :" + responseString);
        }
        return responseString;
    }

    protected String getTransaction(String url, String transactionId, String clientId,
                                    String username,
                                    String password) throws IOException {

        log.debug("Started handling transaction creation");
        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));
        HttpsURLConnection connection = null;
        String responseString = "";

        url = url + "?transaction_id=" + transactionId + "&client_id=" + clientId;
        try {
            connection = (HttpsURLConnection) new URL(url).openConnection();

            connection.setRequestMethod(MepinConstants.HTTP_GET);
            connection.setRequestProperty(MepinConstants.HTTP_ACCEPT, MepinConstants.HTTP_CONTENT_TYPE);
            connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION, MepinConstants.HTTP_AUTHORIZATION_BASIC + encoding);

            String response = "";
            int statusCode = connection.getResponseCode();
            InputStream is;
            if ((statusCode == 200) || (statusCode == 201)) {
                is = connection.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String output;
                while ((output = br.readLine()) != null) {
                    responseString += output;
                }
                br.close();
            } else {
                is = connection.getErrorStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String output;
                while ((output = br.readLine()) != null) {
                    responseString += output;
                }
                br.close();
                if (log.isDebugEnabled()) {
                    log.debug("MePIN Status Response: " + response);
                }
                return MepinConstants.FAILED;
            }

        } catch (IOException e) {
            throw new IOException(e.getMessage(), e);
        } finally {
            connection.disconnect();
        }
        return responseString;
    }

    public String getUserInformation(String username, String password, String accessToken)
            throws AuthenticationFailedException {
        String responseString = "";
        HttpsURLConnection connection = null;
        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));
        try {
            String query = String.format("access_token=%s",
                                         URLEncoder.encode(accessToken, MepinConstants.CHARSET));

            connection = (HttpsURLConnection) new URL(MepinConstants.MEPIN_GET_USER_INFO_URL + "?" + query).openConnection();
            connection.setRequestMethod(MepinConstants.HTTP_GET);
            connection.setRequestProperty(MepinConstants.HTTP_ACCEPT, MepinConstants.HTTP_CONTENT_TYPE);
            connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION, MepinConstants.HTTP_AUTHORIZATION_BASIC + encoding);
            int status = connection.getResponseCode();
            if (log.isDebugEnabled()) {
                log.debug("MePIN Response Code :" + status);
            }
            if (status == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                responseString = sb.toString();
                if (log.isDebugEnabled()) {
                    log.debug("MePIN Response :" + responseString);
                }
            } else {
                return MepinConstants.FAILED;
            }

        } catch (IOException e) {
            throw new AuthenticationFailedException(MepinConstants.MEPIN_ID_NOT_FOUND, e);
        } finally {
            connection.disconnect();
        }
        return responseString;
    }
}