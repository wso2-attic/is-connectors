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

package org.wso2.carbon.identity.authenticator;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.lang.Integer;
import java.net.*;
import java.util.*;

import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;

/**
 * Authenticator of Tiqr
 */
public class TiqrAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(TiqrAuthenticator.class);

    private String enrolUserBody = null;
    private String qrCode = null;
    private String sessionId = null;
    private boolean isCompleted = false;

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        if(context.isLogoutRequest()) {
            isCompleted = false;
        }
        return super.process(request, response, context);
    }
    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside TiqrAuthenticator.canHandle()");
        }
        return (qrCode != null && qrCode.startsWith("<img alt=\"QR\""));
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            if (!isCompleted && enrolUserBody == null) {
                Map<String, String> authenticatorProperties = context
                        .getAuthenticatorProperties();
                if (authenticatorProperties != null) {
                    enrolUserBody = enrolUser(authenticatorProperties);
                    if (enrolUserBody == null) {
                        throw new AuthenticationFailedException("Error while getting the QR code");
                    } else {
                        postContent(response, enrolUserBody);
                        if (log.isDebugEnabled()) {
                            log.debug("The QR code is successfully displayed.");
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                    }
                    throw new AuthenticationFailedException(
                            "Error while retrieving properties. Authenticator Properties cannot be null");
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception while showing the QR code: " + e.getMessage(), e);
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException("Exception while showing the QR code: " + e.getMessage(), e);
        } catch (IndexOutOfBoundsException e) {
            throw new AuthenticationFailedException("Unable to get QR code: " + e.getMessage(), e);
        } finally {
            isCompleted = false;
        }
        return;
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property userId = new Property();
        userId.setName(TiqrConstants.ENROLL_USERID);
        userId.setDisplayName("User Id");
        userId.setRequired(true);
        userId.setDescription("Enter user identifier to entroll the user in Tiqr");
        configProperties.add(userId);

        Property displayName = new Property();
        displayName.setName(TiqrConstants.ENROLL_DISPLAYNAME);
        displayName.setDisplayName("Display Name");
        displayName.setRequired(true);
        displayName.setDescription("Enter user's display name to entrol the user in Tiqr");
        configProperties.add(displayName);

        Property clientIP = new Property();
        clientIP.setName(TiqrConstants.TIQR_CLIENTIP);
        clientIP.setDisplayName("Client IP");
        clientIP.setRequired(true);
        clientIP.setDescription("Enter the IP address of the tiqr client");
        configProperties.add(clientIP);

        Property waitTime = new Property();
        waitTime.setName(TiqrConstants.TIQR_WAIT_TIME);
        waitTime.setDisplayName("Wait Time");
        waitTime.setRequired(true);
        waitTime.setDescription("Period of waiting to terminate the authentication (in seconds)");
        configProperties.add(waitTime);
        return configProperties;
    }

    /**
     * Process the response of the Tiqr end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
        AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            String tiqrEP = getTiqrEndpoint(authenticatorProperties);
            if (tiqrEP == null) {
                tiqrEP = "http://" + authenticatorProperties.get(TiqrConstants.TIQR_CLIENTIP)
                        + ":8080";
            }
            String urlToCheckEntrolment = tiqrEP + "/enrol.php";
            int status = 0;
            log.info("Waiting for getting enrolment status...");
            int retry = 0;
            int retryInterval = 1000;
            int retryCount = Integer.parseInt(authenticatorProperties.get(TiqrConstants.TIQR_WAIT_TIME));
            while (retry < retryCount) {
                try {
                    String res = sendRESTCall(urlToCheckEntrolment, "", "action=getStatus&sessId=" + sessionId, "POST");
                    if (res.startsWith("Failed:")) {
                        throw new AuthenticationFailedException("Unable to connect to the Tiqr: " + res.replace("Failed: ", ""));
                    }
                    status = Integer.parseInt(res.substring(res.indexOf("Enrolment status: "), res.indexOf("<!DOCTYPE")).replace("Enrolment status: ", "").trim());
                    if (log.isDebugEnabled()) {
                        log.debug("Enrolment status: " + status);
                    }
                    if (status == 5) {
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully enrolled the user with User ID:"
                                    + authenticatorProperties.get(TiqrConstants.ENROLL_USERID)
                                    + "and Display Name:" + authenticatorProperties.get(TiqrConstants.ENROLL_DISPLAYNAME));
                        }
                        break;
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Enrolment pending...");
                    }
                    Thread.sleep(retryInterval);
                    retry++;
                    if (retry == retryCount) {
                        log.warn("Enrolment timed out.");
                        break;
                    }
                } catch (InterruptedException e) {
                    throw new AuthenticationFailedException(
                            "Interruption occured while getting the enrolment status" + e.getMessage(), e);
                } catch (NumberFormatException e) {
                    throw new AuthenticationFailedException("Error while getting the enrolment status"
                            + e.getMessage(), e);
                } catch (IndexOutOfBoundsException e) {
                    throw new AuthenticationFailedException("Error while getting the enrolment status"
                            + e.getMessage(), e);
                }
            }
            if (status == 5) {
                context.setSubject("an authorised user");
                log.info("Successfully enrolled the user");
            } else {
                context.setSubject("Enrolment process is failed");
                throw new AuthenticationFailedException("Enrolment process is Failed");
            }
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } finally {
            isCompleted = true;
            qrCode = null;
            enrolUserBody = null;
            sessionId = null;
        }
    }

    /**
     * Connect with the tiqr client
     */
    public String enrolUser(Map<String, String> authenticatorProperties) {
        String tiqrEP = getTiqrEndpoint(authenticatorProperties);
        if (tiqrEP == null) {
            tiqrEP = "http://" + authenticatorProperties.get(TiqrConstants.TIQR_CLIENTIP)
                    + ":8080";
        }
        String urlToEntrol = tiqrEP + "/enrol.php";
        String userId = authenticatorProperties
                .get(TiqrConstants.ENROLL_USERID);
        String diaplayName = authenticatorProperties
                .get(TiqrConstants.ENROLL_DISPLAYNAME);
        String waitTime = authenticatorProperties
                .get(TiqrConstants.TIQR_WAIT_TIME);
        if (userId != null && diaplayName != null && waitTime != null) {
            String formParameters = "uid=" + userId + "&displayName=" + diaplayName;
            String result = sendRESTCall(urlToEntrol, "", formParameters, "POST");
            try {
                if (result.startsWith("Failed:")) {
                    if (log.isDebugEnabled()) {
                        log.error("Unable to find QR code");
                    }
                    return null;
                }
                sessionId = result.substring(result.indexOf("Session id: ["), result.indexOf("'/>")).replace("Session id: [", "").replace("]", "").trim();
                if (!result.contains("Session id: [")) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unable to find the Session ID");
                    }
                    return null;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Tiqr Session ID: " + sessionId);
                }
                if (!result.contains("<img") || !result.contains("</body>")) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unable to find QR code");
                    }
                    return null;
                }
                qrCode = result.substring(result.indexOf("<img"), result.indexOf("</body>"));
                return qrCode;
            } catch (IndexOutOfBoundsException e) {
                log.error("Error while getting the QR code" + e.getMessage());
                return null;
            }
        } else {
            log.error("Required parameters should be given");
            return null;
        }
    }

    /**
     * Get the QR code
     */
    public String sendRESTCall(String url, String urlParameters, String formParameters, String httpMethod) {
        String line;
        StringBuffer responseString = new StringBuffer();
        try {
            URL tiqrEP = new URL(url + urlParameters);

            String encodedData = formParameters;

            HttpURLConnection connection = (HttpURLConnection) tiqrEP.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(httpMethod);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            if (httpMethod.toUpperCase().equals("POST")) {
                OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream(), "UTF-8");
                writer.write(encodedData);
                writer.close();
            }
            if (connection.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                while ((line = br.readLine()) != null) {
                    responseString.append(line);
                }
                br.close();
            }
            connection.disconnect();
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed: " + e.getMessage());
            }
            return "Failed: " + e.getMessage();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed: " + e.getMessage());
            }
            return "Failed: " + e.getMessage();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed: " + e.getMessage());
            }
            return "Failed: " + e.getMessage();
        }
        String rs = responseString.toString();
        return rs;
    }

    /**
     * Display the QR code
     */
    public void postContent(HttpServletResponse response, String image)
            throws IOException {
        response.setContentType("text/html");
        PrintWriter out = null;
        try {
            out = response.getWriter();
            response.setIntHeader("Refresh", 1);
            out.println("<title>Tiqr QR</title>" +
                    "<body bgcolor=FFFFFF>");
            out.println("<h2>Scan this QR</h2><br/>" + image);
            out.println("</body");
            out.close();
            if (log.isDebugEnabled()) {
                log.debug("The QR code is successfully displayed.");
            }
        } catch (IOException e) {
            log.error("Unable to show the QR code");
        }
    }

    /**
     * Get the tiqr end-point
     */
    protected String getTiqrEndpoint(
            Map<String, String> authenticatorProperties) {
        return "http://" + authenticatorProperties.get(TiqrConstants.TIQR_CLIENTIP)
                + ":8080";
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return TiqrConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return TiqrConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }
}

