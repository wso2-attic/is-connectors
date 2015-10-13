/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.SecureRandom;


public class CheckPushResult {
    private static final Log log = LogFactory.getLog(CheckPushResult.class);

    private static String urlString = "https://api.myinwebo.com/FS?";
    private String serviceId;
    private String p12file;
    private String p12password;
    private SSLContext context = null;

    public CheckPushResult(String id, String p12file, String p12password) {
        this.serviceId = id;
        this.p12file = p12file;
        this.p12password = p12password;
    }

    /**
     * Set the client certificate to Default SSL Context
     *
     * @param certificateFile File containing certificate (PKCS12 format)
     * @param certPassword    Password of certificate
     * @throws Exception
     */
    public static SSLContext setHttpsClientCert(String certificateFile, String certPassword)
            throws Exception {
        if (certificateFile == null || !new File(certificateFile).exists()) {
            return null;
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        InputStream keyInput = new FileInputStream(certificateFile);
        keyStore.load(keyInput, certPassword.toCharArray());

        keyInput.close();
        keyManagerFactory.init(keyStore, certPassword.toCharArray());

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        SSLContext.setDefault(context);
        return context;
    }

    /**
     * Prompt for a login and an OTP and check if they are OK.
     */
    public JSONObject checkPushResult(String login, String sessionId) {
        String urlParameters = null;
        JSONObject json = null;
        try {
            urlParameters = "action=checkPushResult"
                    + "&serviceId=" + URLEncoder.encode("" + serviceId, "UTF-8")
                    + "&userId=" + URLEncoder.encode(login, "UTF-8")
                    + "&sessionId=" + URLEncoder.encode(sessionId, "UTF-8")
                    + "&format=json";
        } catch (UnsupportedEncodingException e1) {
            log.info("Error while encoding the Url" + e1.getMessage(), e1);
            json.put("err", "NOK:urlParams");
        }
        try {
            if (this.context == null) {
                try {
                    this.context = setHttpsClientCert(this.p12file, this.p12password);
                } catch (Exception e) {
                    log.error("Error while adding the certificate" + e.getMessage(), e);
                }
            }
            SSLSocketFactory sslsocketfactory = context.getSocketFactory();
            URL url = null;
            try {
                url = new URL(urlString + urlParameters);
            } catch (MalformedURLException e) {
                log.error("Error while creating the URL" + e.getMessage(), e);
            }
            HttpsURLConnection conn = null;
            try {
                if (url != null) {
                    conn = (HttpsURLConnection) url.openConnection();
                }
            } catch (IOException e) {
                log.error("Error while creating the connection" + e.getMessage(), e);
            }
            conn.setSSLSocketFactory(sslsocketfactory);
            try {
                if (conn != null) {
                    conn.setRequestMethod("GET");
                }
            } catch (ProtocolException e) {
                log.error("Error while setting the request" + e.getMessage(), e);
            }
            InputStream is = null;
            try {
                if (conn != null) {
                    is = conn.getInputStream();
                }
            } catch (IOException e) {
                log.error("Error while getting the input" + e.getMessage(), e);
            }
            BufferedReader br = null;
            try {
                if (is != null) {
                    br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                }
            } catch (UnsupportedEncodingException e) {
                log.error("Error while encoding the input" + e.getMessage(), e);
            }
            JSONParser parser = new JSONParser();
            try {
                json = (JSONObject) parser.parse(br);
            } catch (IOException e) {
                log.error("Error while getting response " + e.getMessage(), e);
            } catch (ParseException e) {
                log.error("Error while parsing the json object " + e.getMessage(), e);
            }
        } catch (Exception e) {
            json.put("err", "NOK:connection");
        }
        return json;
    }

}
