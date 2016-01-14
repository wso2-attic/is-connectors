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

package org.wso2.carbon.identity.authenticator.mailChimp;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of MailChimp
 */
public class MailChimpAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(MailChimpAuthenticator.class);

    /**
     * Get MailChimp authorization endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map< String, String > authenticatorProperties) {
        return MailChimpAuthenticatorConstants.MailChimp_OAUTH_ENDPOINT;
    }

    /**
     * Get MailChimp token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map< String, String > authenticatorProperties) {
        return MailChimpAuthenticatorConstants.MailChimp_TOKEN_ENDPOINT;
    }

    /**
     * Get MailChimp user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map< String, String > authenticatorProperties) {
//        return MailChimpAuthenticatorConstants.MailChimp_USERINFO_ENDPOINT;
        return null;
    }

    /**
     * Check ID token in MailChimp OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map< String, String > authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return MailChimpAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return MailChimpAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List< Property > getConfigurationProperties() {
        List< Property > configProperties = new ArrayList< Property >();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter mailChimp client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter mailChimp client secret value");
        clientSecret.setDisplayOrder(1);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter the callback url");
        callbackUrl.setDisplayOrder(2);
        configProperties.add(callbackUrl);

        return configProperties;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            String callbackUrl = getCallbackUrl(authenticatorProperties);
            OAuthAuthzResponse authorizationResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authorizationResponse.getCode();
            OAuthClientRequest accessRequest =
                    getAccessRequest(tokenEndPoint, clientId, code, clientSecret, callbackUrl);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessRequest);
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }
            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);
            Map<ClaimMapping, String> claims;
//            AuthenticatedUser authenticatedUserObj;
//            log.info("XXXXXXXXXXXXXXXXXXXXX"+oAuthResponse.getParam(MailChimpAuthenticatorConstants.USER_ID));
//            authenticatedUserObj = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(oAuthResponse
//                    .getParam(MailChimpAuthenticatorConstants.USER_ID));
//            authenticatedUserObj.setAuthenticatedSubjectIdentifier(oAuthResponse
//                    .getParam(MailChimpAuthenticatorConstants.USER_ID));
//            claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
//            authenticatedUserObj.setUserAttributes(claims);
//            context.setSubject(authenticatedUserObj);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {
        OAuthClientResponse oAuthResponse = null;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while requesting access token", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthProblemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while requesting access token", e);
            }
        }
        return oAuthResponse;
    }

    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
                                                String callbackurl) throws AuthenticationFailedException {
        OAuthClientRequest accessRequest;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret)
                    .setCode(code)
                    .setRedirectURI(callbackurl)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while building request for request access token", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return accessRequest;
    }

    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException("Error while retrieving properties. Authenticator Properties cannot be null");
            } else {
                String clientId = (String) authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = this.getAuthorizationServerEndpoint(authenticatorProperties);
                if (authorizationEP == null) {
                    authorizationEP = (String) authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
                }
                String callbackurl = this.getCallbackUrl(authenticatorProperties);
                if (StringUtils.isBlank(callbackurl)) {
                    callbackurl = IdentityUtil.getServerURL("redirectUri", true, true);
                }
                String state = context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
                state = this.getState(state, authenticatorProperties);
                String queryString = this.getQueryString(authenticatorProperties);
                OAuthClientRequest oAuthClientRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callbackurl)
                        .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state)
                        .buildQueryMessage();
                String locationUri = oAuthClientRequest.getLocationUri();
                String domain = request.getParameter("domain");
                if (!StringUtils.isEmpty(domain)) {
                    locationUri = locationUri + "&fidp=" + domain;
                }
                if (!StringUtils.isEmpty(queryString)) {
                    if (!queryString.startsWith("&")) {
                        locationUri = locationUri + "&" + queryString;
                    } else {
                        locationUri = locationUri + queryString;
                    }
                }
                response.sendRedirect(locationUri);
            }
        } catch (IOException e) {
            log.error("Exception while sending to the login page", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e1) {
            log.error("Exception while building authorization code request", e1);
            throw new AuthenticationFailedException(e1.getMessage(), e1);
        }
    }

}

