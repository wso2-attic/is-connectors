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
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

/**
 * Authenticator for Yammer
 */
public class YammerOAuth2Authenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -1179165995021182755L;
    private static Log log = LogFactory.getLog(YammerOAuth2Authenticator.class);

    /**
     * @return
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map< String, String > authenticatorProperties) {
        return YammerOAuth2AuthenticatorConstants.YAMMER_OAUTH_ENDPOINT;
    }

    /**
     * @return
     */
    @Override
    protected String getTokenEndpoint(Map< String, String > authenticatorProperties) {
        return YammerOAuth2AuthenticatorConstants.YAMMER_TOKEN_ENDPOINT;
    }

    /**
     * @return
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map< String, String > authenticatorProperties) {
        return YammerOAuth2AuthenticatorConstants.YAMMER_USERINFO_ENDPOINT;
    }

    /**
     * Always return false as there is no ID token in Yammer OAuth.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return False
     */
    @Override
    protected boolean requiredIDToken(Map< String, String > authenticatorProperties) {
        return false;
    }

    @Override
    public String getFriendlyName() {
        return YammerOAuth2AuthenticatorConstants.YAMMER_CONNECTOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return YammerOAuth2AuthenticatorConstants.YAMMER_CONNECTOR_NAME;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map< String, String > authenticatorProperties = context.getAuthenticatorProperties();

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
            String token = oAuthResponse.getParam(YammerOAuth2AuthenticatorConstants.TOKEN);
            String accessToken = JSONUtils.parseJSON(token).get(YammerOAuth2AuthenticatorConstants.ACCESS_TOKEN).toString();
            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }

            AuthenticatedUser authenticatedUserObj;
            Map< ClaimMapping, String > claims;
            authenticatedUserObj = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(JSONUtils.parseJSON(token).get(YammerOAuth2AuthenticatorConstants.USER_ID).toString());
            authenticatedUserObj.setAuthenticatedSubjectIdentifier(JSONUtils.parseJSON(token).get(YammerOAuth2AuthenticatorConstants.USER_ID).toString());
            claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
            authenticatedUserObj.setUserAttributes(claims);
            context.setSubject(authenticatedUserObj);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    /**
     * Builds request for access token
     * @param tokenEndPoint yammer assess token endpoint
     * @param clientId client id of app
     * @param code authorization code
     * @param clientSecret client secret of the app
     * @param callbackurl redirect url
     * @return
     * @throws AuthenticationFailedException
     */
    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
                                                String callbackurl)
            throws AuthenticationFailedException {
        OAuthClientRequest accessRequest;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientId)
                    .setClientSecret(clientSecret).setRedirectURI(callbackurl).setCode(code)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return accessRequest;
    }

    /**
     * Get auth2 response
     * @param oAuthClient oauth client
     * @param accessRequest Built request for access token
     * @return
     * @throws AuthenticationFailedException
     */
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
     * Get subject attributes.
     *
     * @param token                   OAuthClientResponse
     * @param authenticatorProperties Map<String, String>
     * @return Map<ClaimMapping, String> Claim mappings.
     */
    @Override
    protected Map< ClaimMapping, String > getSubjectAttributes(OAuthClientResponse token,
                                                               Map< String, String > authenticatorProperties) {
        Map< ClaimMapping, String > claims = new HashMap<>();
        try {
            String jsonString = token.getParam(YammerOAuth2AuthenticatorConstants.TOKEN);
            String accessToken = JSONUtils.parseJSON(jsonString).get(YammerOAuth2AuthenticatorConstants.ACCESS_TOKEN).toString();
            String url = getUserInfoEndpoint(token, authenticatorProperties);

            String json = sendRequest(url, accessToken);
            if (StringUtils.isBlank(json)) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to fetch user claims. Proceeding without user claims");
                }
                return claims;
            }
            Map< String, Object > jsonObject = JSONUtils.parseJSON(json);
            for (Map.Entry< String, Object > data : jsonObject.entrySet()) {
                String key = data.getKey();
                claims.put(ClaimMapping.build(key, key, null, false), jsonObject.get(key).toString());
                if (log.isDebugEnabled()) {
                    log.debug("Adding claims from end-point data mapping : " + key + " - " +
                            jsonObject.get(key).toString());
                }
            }
        } catch (Exception e) {
            log.error("Error occurred while accessing user info endpoint", e);
        }
        return claims;
    }

    @Override
    public List< Property > getConfigurationProperties() {
        List< Property > configProperties = new ArrayList< Property >();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Yammer client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Yammer client secret value");
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