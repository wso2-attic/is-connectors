/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.authenticator.basecamp;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.parameters.OAuthParametersApplier;
import org.apache.oltu.oauth2.common.parameters.QueryParameterApplier;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Iterator;

/**
 * Authenticator of Basecamp
 */
public class BasecampAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(BasecampAuthenticator.class);

    /**
     * Get Basecamp authorization endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return BasecampAuthenticatorConstants.BASECAMP_OAUTH_ENDPOINT;
    }

    /**
     * Get Basecamp token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return BasecampAuthenticatorConstants.BASECAMP_TOKEN_ENDPOINT;
    }

    /**
     * Get Basecamp user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return BasecampAuthenticatorConstants.BASECAMP_USERINFO_ENDPOINT;
    }

    /**
     * Check ID token in Basecamp OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return BasecampAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return BasecampAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException, LogoutFailedException {
        if (context.isLogoutRequest()) {
            try {
                if (!this.canHandle(request)) {
                    context.setCurrentAuthenticator(this.getName());
                    initiateLogoutRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                } else {
                    processLogoutResponse(request, response, context);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } catch (UnsupportedOperationException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Ignoring UnsupportedOperationException.", e);
                }
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException("Error while retrieving properties. Authenticator Properties cannot be null");
            } else {
                String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = this.getAuthorizationServerEndpoint(authenticatorProperties);
                if (StringUtils.isEmpty(authorizationEP)) {
                    authorizationEP = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
                }
                String callbackurl = this.getCallbackUrl(authenticatorProperties);
                if (StringUtils.isBlank(callbackurl)) {
                    callbackurl = IdentityUtil.getServerURL("commonauth", true, true);
                }
                String state = context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
                state = this.getState(state, authenticatorProperties);
                String queryString = this.getQueryString(authenticatorProperties);
                OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                        .setClientId(clientId).setRedirectURI(callbackurl).setState(state).buildQueryMessage();

                Map<String, Object> additionalParameters = new HashMap();
                OAuthParametersApplier applier = new QueryParameterApplier();
                additionalParameters.put("type", BasecampAuthenticatorConstants.OAUTH2_TYPE_WEB_SERVER);
                authzRequest = (OAuthClientRequest) applier.applyOAuthParameters(authzRequest, additionalParameters);

                String redirectURL = authzRequest.getLocationUri();
                if (!StringUtils.isEmpty(queryString)) {
                    if (!queryString.startsWith("&")) {
                        redirectURL = redirectURL + "&" + queryString;
                    } else {
                        redirectURL = redirectURL + queryString;
                    }
                }
                response.sendRedirect(redirectURL);
            }
        } catch (IOException e) {
            log.error("Exception while sending to the login page", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            log.error("Exception while building authorization code request", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Process the response of first call
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            String callbackUrl = getCallbackUrl(authenticatorProperties);
            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authzResponse.getCode();
            OAuthClientRequest accessRequest =
                    getAccessRequest(tokenEndPoint, clientId, code, clientSecret, callbackUrl);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessRequest);
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }
            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);
            Map<ClaimMapping, String> claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
            String email = claims.get(ClaimMapping.build(BasecampAuthenticatorConstants.BASECAMP_EMAIL_ADDRESS
                    , BasecampAuthenticatorConstants.BASECAMP_EMAIL_ADDRESS, (String) null, false));
            AuthenticatedUser authenticatedUserObj =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(email);
            authenticatedUserObj.setAuthenticatedSubjectIdentifier(email);
            authenticatedUserObj.setUserAttributes(claims);
            context.setSubject(authenticatedUserObj);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
                                                String callbackurl)
            throws AuthenticationFailedException {
        OAuthClientRequest accessRequest;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret).setRedirectURI(callbackurl).setCode(code)
                    .buildBodyMessage();
            Map<String, Object> additionalParameters = new HashMap();
            OAuthParametersApplier applier = new QueryParameterApplier();
            additionalParameters.put("type", BasecampAuthenticatorConstants.OAUTH2_TYPE_WEB_SERVER);
            accessRequest = (OAuthClientRequest) applier.applyOAuthParameters(accessRequest, additionalParameters);
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return accessRequest;
    }

    @Override
    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        HashMap claims = new HashMap();
        try {
            String accessToken = token.getParam("access_token");
            String url = this.getUserInfoEndpoint(token, authenticatorProperties);
            String json = this.sendRequest(url, accessToken);
            if (StringUtils.isBlank(json)) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to fetch user claims. Proceeding without user claims");
                }
                return claims;
            }
            JSONObject obj = new JSONObject(json);
            String userData = obj.getJSONObject("identity").toString();
            Map jsonObject = JSONUtils.parseJSON(userData);
            Iterator i$ = jsonObject.entrySet().iterator();
            while (i$.hasNext()) {
                Map.Entry data = (Map.Entry) i$.next();
                String key = (String) data.getKey();
                claims.put(ClaimMapping.build(key, key, (String) null, false), jsonObject.get(key).toString());
                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable("UserClaims")) {
                    log.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key).toString());
                }
            }
        } catch (Exception e) {
            log.error("Error occurred while accessing user info endpoint", e);
        }
        return claims;
    }

    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {
        OAuthClientResponse oAuthResponse = null;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return oAuthResponse;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Basecamp client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Basecamp client secret value");
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
}

