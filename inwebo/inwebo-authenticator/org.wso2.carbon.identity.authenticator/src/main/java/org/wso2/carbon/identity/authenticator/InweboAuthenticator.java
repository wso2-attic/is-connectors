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
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;

/**
 * Authenticator of Inwebo
 */
public class InweboAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(InweboAuthenticator.class);
    private static final long serialVersionUID = -4154255583070524018L;
    private String p12file;
    private String p12password;

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside InweboAuthenticator.canHandle()");
        }
        String userId = request.getParameter(InweboConstants.USER_ID);
        String serviceId = request.getParameter(InweboConstants.SERVICE_ID);
        if (userId != null && serviceId != null) {
            return true;
        }
        return false;
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String userId = authenticatorProperties.get(InweboConstants.USER_ID);
                String serviceId = authenticatorProperties.get(InweboConstants.SERVICE_ID);
                p12file = authenticatorProperties.get(InweboConstants.INWEBO_P12FILE);
                p12password = authenticatorProperties.get(InweboConstants.INWEBO_P12PASSWORD);

                if (userId != null && serviceId != null && p12file != null && p12password != null) {
                    try {
                        CheckPushResult.setHttpsClientCert(p12file, p12password);
                    }catch (Exception e){
                        log.error("Error while adding the certificate" + e.getMessage(), e);

                    }
                    PushREST push;
                    push = new PushREST(serviceId, p12file, p12password, userId);
                    push.run();
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
        p12file.setDisplayName("P12FILE");
        p12file.setRequired(true);
        p12file.setDescription("Enter your p12_file path");
        configProperties.add(p12file);

        Property p12password = new Property();
        p12password.setName(InweboConstants.INWEBO_P12PASSWORD);
        p12password.setDisplayName("P12Password");
        p12password.setRequired(true);
        p12password.setDescription("Enter your p12_password");
        configProperties.add(p12password);        return configProperties;
    }

    /**
     * Process the response of the Inwebo end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
        AuthenticationContext context) throws AuthenticationFailedException {
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
        return InweboConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }
}

