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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.apache.amber.oauth2.common.utils.JSONUtils;


/**
 * Authenticator of Inwebo
 */
public class InweboAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(InweboAuthenticator.class);
    private static final long serialVersionUID = -4154255583070524018L;
    private String pushResponse = null;


    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside InweboAuthenticator.canHandle()");
        }
        return (pushResponse != null && pushResponse.contains(InweboConstants.PUSHRESPONSE));
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            if (pushResponse == null) {
                Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
                if (authenticatorProperties != null) {
                    String relyingParty = request.getParameterValues("relyingParty")[0];
                    String type = request.getParameterValues("type")[0];
                    String referer = request.getHeader("referer").toString();
                    String finalReferer = "";
                    if ((referer.charAt(referer.lastIndexOf(":") + 5) + "").equals("/")) {
                        finalReferer = referer.substring(0, referer.lastIndexOf(":") + 5);
                    } else if ((referer.charAt(referer.lastIndexOf(":") + 3) + "").equals("/")) {
                        finalReferer = referer.substring(0, referer.lastIndexOf(":") + 3);
                    }
                    String userId = authenticatorProperties.get(InweboConstants.USER_ID);
                    String serviceId = authenticatorProperties.get(InweboConstants.SERVICE_ID);
                    String p12file = authenticatorProperties.get(InweboConstants.INWEBO_P12FILE);
                    String p12password = authenticatorProperties.get(InweboConstants.INWEBO_P12PASSWORD);
                    int retryCount = Integer.parseInt(authenticatorProperties.get(InweboConstants.RETRYCOUNT));
                    int retryInterval = Integer.parseInt(authenticatorProperties.get(InweboConstants.RETRINTERVAL));

                    if (userId != null && serviceId != null && p12file != null && p12password != null) {
                        PushREST push;
                        push = new PushREST(serviceId, p12file, p12password, userId, retryCount, retryInterval);
                        pushResponse = push.run();
                        PushREST.showServlet(response, relyingParty, type, finalReferer);
                    }
                }
            }
        } catch (Exception e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
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

        userId.setName(InweboConstants.USER_ID);
        userId.setDisplayName("User name");
        userId.setRequired(true);
        userId.setDescription("Enter your Inwebo UserName");
        configProperties.add(userId);

        Property serviceId = new Property();
        serviceId.setName(InweboConstants.SERVICE_ID);
        serviceId.setDisplayName("Service Id");
        serviceId.setRequired(true);
        serviceId.setDescription("Enter your service Id");
        configProperties.add(serviceId);

        Property p12file = new Property();
        p12file.setName(InweboConstants.INWEBO_P12FILE);
        p12file.setDisplayName("Certificate File");
        p12file.setRequired(true);
        p12file.setDescription("Enter your p12_file path");
        configProperties.add(p12file);

        Property p12password = new Property();
        p12password.setName(InweboConstants.INWEBO_P12PASSWORD);
        p12password.setDisplayName("Certificate Password");
        p12password.setRequired(true);
        p12password.setConfidential(true);
        p12password.setDescription("Enter your p12_password");
        configProperties.add(p12password);

        Property retryCount = new Property();
        retryCount.setName(InweboConstants.RETRYCOUNT);
        retryCount.setDisplayName("Retry Count");
        retryCount.setRequired(true);
        retryCount.setDescription("Number of attempts waiting for authentication(<10)");
        configProperties.add(retryCount);

        Property retryInterval = new Property();
        retryInterval.setName(InweboConstants.RETRINTERVAL);
        retryInterval.setDisplayName("Retry Interval");
        retryInterval.setRequired(true);
        retryInterval.setDescription("Period of time for waiting eg:1000");
        configProperties.add(retryInterval);
        return configProperties;

    }

    /**
     * Process the response of the Inwebo end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        if (pushResponse.contains(InweboConstants.PUSHRESPONSE)) {
            log.info("Authentication Successful");
            context.setSubject("Success");
            Map<String, Object> userClaims = getUserClaims();
            if (userClaims != null && !userClaims.isEmpty()) {
                context.setSubjectAttributes(getSubjectAttributes(userClaims));
                context.setSubject("Authentication Success");
            } else {
                throw new AuthenticationFailedException("Selected user profile found");
            }
        } else
            throw new AuthenticationFailedException("Authentication failed");
        pushResponse = null;
    }

    protected Map<ClaimMapping, String> getSubjectAttributes(
            Map<String, Object> claimMap) {

        Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();

        if (claimMap != null) {
            for (Map.Entry<String, Object> entry : claimMap.entrySet()) {
                claims.put(ClaimMapping.build(entry.getKey(),
                        entry.getKey(), null, false), entry.getValue()
                        .toString());
                if (log.isDebugEnabled()) {
                    log.debug("Adding claim from end-point data mapping : "
                            + entry.getKey() + " <> " + " : "
                            + entry.getValue());
                }

            }
        }

        return claims;
    }

    protected Map<String, Object> getUserClaims() {
        try {
            String json = pushResponse;

            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);

            return jsonObject;
        } catch (Exception e) {
            log.error(e);
        }
        return new HashMap<String, Object>();

    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return InweboConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return InweboConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }
}

