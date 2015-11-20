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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of SMSOTP
 */
public class SMSOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(SMSOTPAuthenticator.class);
    AuthenticationContext authContext = new AuthenticationContext();
    private String otpToken;
    private String mobile;

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
//    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside SMSOTPAuthenticator canHandle method");
        }
        return !StringUtils.isEmpty(request.getParameter(SMSOTPConstants.CODE));
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        
        OneTimePassword token = new OneTimePassword();
        String secret = OneTimePassword.getRandomNumber(SMSOTPConstants.SECRET_KEY_LENGTH);
        otpToken = token.generateToken(secret, "" + SMSOTPConstants.NUMBER_BASE, SMSOTPConstants.NUMBER_DIGIT);
        Object myToken = otpToken;
        authContext.setProperty(otpToken, myToken);

        System.out.println("hh " + myToken);
        Map<String, String> authenticatorProperties = context
                .getAuthenticatorProperties();
        String clientId = authenticatorProperties
                .get(SMSOTPConstants.API_KEY);
        String clientSecret = authenticatorProperties
                .get(SMSOTPConstants.API_SECRET);

        String loginPage = "/authenticationendpoint/smsotp.jsp";
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(),
                context.getContextIdentifier());
        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
        }

        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) + "&authenticators=" +
                    getName() + retryParam);
        } catch (IOException e) {
            log.error("Authentication failed!", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        String username = null;
        //Getting the last authenticated local user
        for (Integer stepMap: context.getSequenceConfig().getStepMap().keySet())
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {

                username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }

        if (username != null) {

            UserRealm userRealm = getUserRealm();
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                try {
                    mobile = userRealm.getUserStoreManager().getUserClaimValue(username, SMSOTPConstants.MOBILE_CLAIM, null).toString();
                } catch (UserStoreException e) {
                    throw new AuthenticationFailedException("Cannot find the user claim for mobile "+ e.getMessage(),e);
                }
            }
        }

        if (!StringUtils.isEmpty(clientId) && !StringUtils.isEmpty(clientSecret) && !StringUtils.isEmpty(mobile)) {
            String urlParameters = "api_key=" + clientId + "&api_secret=" + clientSecret + "&from=NEXMO&to=" + mobile
                    + "&text=" + otpToken;

//            try {
//                if(!sendRESTCall(SMSOTPConstants.NEXMO_SMS_URL, urlParameters)) {
//                    throw new AuthenticationFailedException("Unable to send the code");
//               }
//            } catch (IOException e) {
//                if (log.isDebugEnabled()) {
//                    log.debug("Error while sending the HTTP request", e);
//                }
//            }
        }
    }

    /**
     * Process the response of the SMSOTP end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String userToken = request.getParameter(SMSOTPConstants.CODE);
        String contextToken = (String) authContext.getProperty(otpToken);
        if (userToken.equals(contextToken)) {
            context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));
        } else {
            throw new AuthenticationFailedException("Code mismatch");
        }
    }

    /**
     * Get the friendly name of the Authenticator
     */
//    @Override
    public String getFriendlyName() {
        return SMSOTPConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
//    @Override
    public String getName() {
        return SMSOTPConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(SMSOTPConstants.API_KEY);
        clientId.setDisplayName("API Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(SMSOTPConstants.API_SECRET);
        clientSecret.setDisplayName("API Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        configProperties.add(clientSecret);

        return configProperties;
    }

    public boolean sendRESTCall(String url, String urlParameters) throws IOException {
        HttpsURLConnection connection = null;
        try {
            URL smsProviderUrl = new URL(url + urlParameters);
            connection = (HttpsURLConnection) smsProviderUrl.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(SMSOTPConstants.HTTP_METHOD);
            if (connection.getResponseCode() == 200) {
                if (log.isDebugEnabled()) {
                    log.debug("Code is successfully sent to your mobile number");
                }
                return true;
            }
            connection.disconnect();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid URL", e);
            }
            throw new MalformedURLException();
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while setting the HTTP method", e);
            }
            throw new ProtocolException();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting the HTTP response", e);
            }
            throw new IOException();
        }
        finally {
            connection.disconnect();
        }
        return false;
    }

    public static UserRealm getUserRealm() {
        return (UserRealm) CarbonContext.getThreadLocalCarbonContext().getUserRealm();
    }

}

