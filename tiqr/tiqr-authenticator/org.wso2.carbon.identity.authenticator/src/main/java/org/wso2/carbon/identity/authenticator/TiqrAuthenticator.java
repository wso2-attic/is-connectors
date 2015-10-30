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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.HttpURLConnection;
import java.lang.Integer;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;

/**
 * Authenticator of Tiqr
 */
public class TiqrAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(TiqrAuthenticator.class);

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
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
        return (request.getParameter(TiqrConstants.ENROLL_USERID) != null
                && request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME) != null);
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = "&authFailure=true&authFailureMsg=enrollment.fail.message";
                }
                String enrollmentPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace("login.do", "tiqr.jsp");
                String queryParams = FrameworkUtils
                        .getQueryStringWithFrameworkContextId(context.getQueryParams(),
                                context.getCallerSessionKey(),
                                context.getContextIdentifier());
                response.sendRedirect(response.encodeRedirectURL(enrollmentPage + ("?" + queryParams))
                        + TiqrConstants.AUTHENTICATORS + getName() + ":" + TiqrConstants.LOCAL + "&"
                        + TiqrConstants.TIQR_CLIENT_IP + "=" + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_IP)
                        + "&" + TiqrConstants.TIQR_CLIENT_PORT + "="
                        + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_PORT) + retryParam);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException(
                        "Error while retrieving properties. Authenticator Properties cannot be null");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception while redirecting the page: " + e.getMessage(), e);
        }
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property clientIP = new Property();
        clientIP.setName(TiqrConstants.TIQR_CLIENT_IP);
        clientIP.setDisplayName("Client IP");
        clientIP.setRequired(true);
        clientIP.setDescription("Enter the IP address of the tiqr client");
        configProperties.add(clientIP);

        Property clientPort = new Property();
        clientPort.setName(TiqrConstants.TIQR_CLIENT_PORT);
        clientPort.setDisplayName("Client IP");
        clientPort.setRequired(true);
        clientPort.setDescription("Enter the port of the tiqr client");
        configProperties.add(clientPort);

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
            if ((StringUtils.isEmpty(request.getParameter(TiqrConstants.ENROLL_USERID))
                    || StringUtils.isEmpty(request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME)))) {
                if (log.isDebugEnabled()) {
                    log.debug("User ID and Full Name cannot not be null");
                }
                log.error("User ID and Full Name cannot not be null");
                throw new InvalidCredentialsException();
            } else if(StringUtils.isEmpty(request.getParameter(TiqrConstants.ENROLL_SESSIONID))) {
                log.error("Unable to connect with the tiqr client");
                throw new AuthenticationFailedException("Unable to connect with the tiqr client");
            }
            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            String tiqrEP = getTiqrEndpoint(authenticatorProperties);
            String urlToCheckEntrolment = tiqrEP + "/enrol.php";
            int status = 0;
            log.info("Waiting for getting enrollment status...");
            int retry = 0;
            int retryInterval = 1000;
            int maxCount = 120;
            int waitTime = Integer.parseInt(authenticatorProperties.get(TiqrConstants.TIQR_WAIT_TIME));
            int retryCount = maxCount > waitTime ? waitTime : maxCount;
            while (retry < retryCount) {
                String checkStatusResponse = sendRESTCall(urlToCheckEntrolment, "", "action=getStatus&sessId="
                        + request.getParameter(TiqrConstants.ENROLL_SESSIONID), TiqrConstants.HTTP_POST);
                if (checkStatusResponse.startsWith(TiqrConstants.FAILED)) {
                    throw new AuthenticationFailedException("Unable to connect to the Tiqr: "
                            + checkStatusResponse.replace(TiqrConstants.FAILED, ""));
                }
                status = Integer.parseInt(checkStatusResponse.substring(checkStatusResponse.indexOf("Enrolment status: "),
                        checkStatusResponse.indexOf("<!DOCTYPE")).replace("Enrolment status: ", "").trim());
                if (log.isDebugEnabled()) {
                    log.debug("Enrolment status: " + status);
                }
                if (status == Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully enrolled the user with User ID:"
                                + request.getParameter(TiqrConstants.ENROLL_USERID)
                                + "and Display Name:" + request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME));
                    }
                    break;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Enrolment pending...");
                }
                Thread.sleep(retryInterval);
                retry++;
                if (retry == retryCount) {
                    log.error("Enrolment timed out.");
                    break;
                }
            }
            if (status == Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS)) {
                context.setSubject(request.getParameter(TiqrConstants.ENROLL_USERID));
                log.info("Successfully enrolled the user");
            } else {
                context.setSubject("Enrolment process is failed");
                throw new AuthenticationFailedException("Enrolment process is Failed");
            }
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        catch (InterruptedException e) {
            throw new AuthenticationFailedException(
                    "Interruption occured while getting the enrollment status" + e.getMessage(), e);
        } catch (IndexOutOfBoundsException e) {
            throw new AuthenticationFailedException("Error while getting the enrollment status"
                    + e.getMessage(), e);
        }
    }

    /**
     * Send REST call
     */
    private String sendRESTCall(String url, String urlParameters, String formParameters, String httpMethod) {
        String line;
        StringBuilder responseString = new StringBuilder();
        HttpURLConnection connection = null;
        try {
            URL tiqrEP = new URL(url + urlParameters);
            connection = (HttpURLConnection) tiqrEP.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(httpMethod);
            connection.setRequestProperty(TiqrConstants.HTTP_CONTENT_TYPE, TiqrConstants.HTTP_CONTENT_TYPE_XWFUE);
            if (httpMethod.toUpperCase().equals(TiqrConstants.HTTP_POST)) {
                OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream(), TiqrConstants.CHARSET);
                writer.write(formParameters);
                writer.close();
            }
            if (connection.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                while ((line = br.readLine()) != null) {
                    responseString.append(line);
                }
                br.close();
            } else {
                return TiqrConstants.FAILED + TiqrConstants.UNABLE_TO_CONNECT;
            }
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } finally {
            connection.disconnect();
        }
        return responseString.toString();
    }

    /**
     * Get the tiqr end-point
     */
    protected String getTiqrEndpoint(
            Map<String, String> authenticatorProperties) {
        return TiqrConstants.PROTOCOL + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_IP)
                + ":" + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_PORT);
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

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }
}