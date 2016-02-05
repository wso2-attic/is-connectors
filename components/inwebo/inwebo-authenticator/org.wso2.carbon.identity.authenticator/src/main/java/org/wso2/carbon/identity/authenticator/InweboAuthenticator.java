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

import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 * Authenticator of Inwebo
 */
public class InweboAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(InweboAuthenticator.class);
    private static final long serialVersionUID = -4154255583070524018L;
    private String pushResponse = null;
    private String userId = null;

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside InweboAuthenticator.canHandle()");
        }
        return (!StringUtils.isEmpty(request.getParameter("inwebo")));
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        loginPage = loginPage.replace(InweboConstants.INWEBO_LOGINPAGE, InweboConstants.INWEBO_PAGE);
        try {
            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = InweboConstants.RETRY_PARAM;
            }
            response.sendRedirect(response.encodeRedirectURL(loginPage + "?" + FrameworkConstants.SESSION_DATA_KEY + "="
                            + context.getContextIdentifier()+retryParam));
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while redirecting", e);
        }
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();
        Property serviceId = new Property();
        serviceId.setName(InweboConstants.SERVICE_ID);
        serviceId.setDisplayName("Service Id");
        serviceId.setRequired(true);
        serviceId.setDescription("Enter your service id");
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
        retryCount.setName(InweboConstants.RETRY_COUNT);
        retryCount.setDisplayName("Waiting Time");
        retryCount.setDescription("Waiting time for authentication in seconds(<10)");
        configProperties.add(retryCount);

        Property retryInterval = new Property();
        retryInterval.setName(InweboConstants.RETRY_INTERVAL);
        retryInterval.setDisplayName("Retry Interval");
        retryInterval.setDescription("Retrying time interval in ms(eg 1000)");
        configProperties.add(retryInterval);

        return configProperties;
    }

    /**
     * Process the response of the Inwebo end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        int waitTime;
        int retryInterval;
        String username = null;

        //Getting the last authenticated local user
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet())
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }
        if (username != null) {
            UserRealm userRealm = null;
            try {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
                username = MultitenantUtils.getTenantAwareUsername(username);
                if (userRealm != null) {
                    userId = userRealm.getUserStoreManager().getUserClaimValue(username, InweboConstants.INWEBO_USERID,
                            null).toString();
                } else {
                    throw new AuthenticationFailedException(
                            "Cannot find the user claim for the given userId: " + userId);
                }
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException("Error while getting the user realm" + e.getMessage(), e);
            }
        }
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if (authenticatorProperties != null) {
            String serviceId = authenticatorProperties.get(InweboConstants.SERVICE_ID);
            String p12file = authenticatorProperties.get(InweboConstants.INWEBO_P12FILE);
            String p12password = authenticatorProperties.get(InweboConstants.INWEBO_P12PASSWORD);
            if (!StringUtils.isEmpty(authenticatorProperties.get(InweboConstants.RETRY_COUNT))) {
                waitTime = Integer.parseInt(authenticatorProperties.get(InweboConstants.RETRY_COUNT));
            } else {
                waitTime = Integer.parseInt(InweboConstants.WAITTIME_DEFAULT);
            }
            if (!StringUtils.isEmpty(authenticatorProperties.get(InweboConstants.RETRY_INTERVAL))) {
                retryInterval = Integer.parseInt(authenticatorProperties.get(InweboConstants.RETRY_INTERVAL
                ));
            } else {
                retryInterval = Integer.parseInt(InweboConstants.RETRYINTERVAL_DEFAULT);
            }
            PushRestCall push = new PushRestCall(serviceId, p12file, p12password, userId, waitTime, retryInterval);
            pushResponse = push.run();

            if (pushResponse.contains(InweboConstants.PUSHRESPONSE)) {
                if (log.isDebugEnabled()) {
                    log.info("Authentication successful");
                }
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userId));
            } else {
                throw new AuthenticationFailedException("Authentication failed");
            }
            pushResponse = null;
            userId = null;
        } else {
            throw new AuthenticationFailedException("Required parameters are empty");
        }
    }
    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
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

