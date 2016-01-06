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
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Foursquare
 */
public class FoursquareAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    public static final long serialVersionUID = -1804204435650065924L;

    private static Log log = LogFactory.getLog(FoursquareAuthenticator.class);

    /**
     * Get the authorization endpoint for Foursquare
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return FoursquareAuthenticatorConstants.FOURSQUARE_OAUTH_ENDPOINT;
    }

    /**
     * Get the token endpoint for Foursquare
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return FoursquareAuthenticatorConstants.FOURSQUARE_TOKEN_ENDPOINT;
    }

    /**
     * Always return false as there is no ID token in Foursquare OAuth.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return False
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    @Override
    public String getFriendlyName() {
        return FoursquareAuthenticatorConstants.FOURSQUARE_CONNECTOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return FoursquareAuthenticatorConstants.FOURSQUARE_CONNECTOR_NAME;
    }

    /**
     * Get configuration properties.
     *
     * @return Properties list.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Foursquare client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Foursquare client secret value");
        clientSecret.setDisplayOrder(1);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter the callback url");
        callbackUrl.setDisplayOrder(2);
        configProperties.add(callbackUrl);

        Property profileVersion = new Property();
        profileVersion.setDisplayName("Profile Version");
        profileVersion.setName(FoursquareAuthenticatorConstants.PROFILE_VERSION);
        profileVersion.setDescription("Enter the profile version");
        profileVersion.setDisplayOrder(3);
        configProperties.add(profileVersion);

        return configProperties;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String profileVersion = authenticatorProperties.get(FoursquareAuthenticatorConstants.PROFILE_VERSION);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            String callbackUrl = getCallbackUrl(authenticatorProperties);

            OAuthAuthzResponse authorizationResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authorizationResponse.getCode();
            OAuthClientRequest accessRequest =
                    getAccessRequest(tokenEndPoint, clientId, code, clientSecret, callbackUrl);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessRequest);

            String accessToken = oAuthResponse.getParam(FoursquareAuthenticatorConstants.ACCESS_TOKEN);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }
            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);

            AuthenticatedUser authenticatedUserObj = null;
            Map<String, Object> userClaims = getUserClaims(oAuthResponse, profileVersion);
            String userId = null;
            if (userClaims != null) {
                userId = (String) userClaims.get(FoursquareAuthenticatorConstants.FOURSQUARE_USER_ID);
            }
            if (userClaims != null) {
                authenticatedUserObj = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(userId);
            }
            if (authenticatedUserObj != null) {
                authenticatedUserObj.setAuthenticatedSubjectIdentifier((String) userClaims.get(FoursquareAuthenticatorConstants.FOURSQUARE_USER_ID));
                authenticatedUserObj.setUserAttributes(getSubjectAttributes(userClaims));
            }
            context.setSubject(authenticatedUserObj);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
                                                String callbackurl) throws AuthenticationFailedException {
        OAuthClientRequest accessRequest;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientId)
                    .setClientSecret(clientSecret).setRedirectURI(callbackurl).setCode(code)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while building request for request access token", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return accessRequest;
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

    @Override
    public String sendRequest(String url, String accessToken) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Claim URL: " + url + " & Access-Token : " + accessToken);
        }

        if (url == null) {
            return "";
        } else {
            URL obj = new URL(url + "&" + FoursquareAuthenticatorConstants.FOURSQUARE_OAUTH2_ACCESS_TOKEN_PARAMETER +
                    "=" + accessToken);
            HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();

            urlConnection.setRequestMethod(FoursquareAuthenticatorConstants.HTTP_METHOD);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            StringBuilder builder = new StringBuilder();
            String inputLine = in.readLine();
            while (inputLine != null) {
                builder.append(inputLine).append("\n");
                inputLine = in.readLine();
            }
            in.close();

            if (log.isDebugEnabled()) {
                log.debug("response: " + builder.toString());
            }
            return builder.toString();
        }
    }

    /**
     * Get the user claim
     *
     * @param token OAuthClientResponse
     * @return
     */
    private Map<String, Object> getUserClaims(OAuthClientResponse token, String profileVersion) {
        Map<String, Object> userClaims;
        try {
            String json = sendRequest(FoursquareAuthenticatorConstants.FOURSQUARE_USER_INFO_ENDPOINT + profileVersion,
                    token.getParam(FoursquareAuthenticatorConstants.ACCESS_TOKEN));
            JSONObject obj = new JSONObject(json);
            String id = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.ID);
            String fName = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.FIRST_NAME);
            String lName = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.LAST_NAME);
            String email = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.CONTACT)
                    .getString(FoursquareAuthenticatorConstants.Claim.EMAIL);
            String gender = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.GENDER);
            String relationship = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.RELATIONSHIP);
            String canonicalUrl = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.CANONICAL_URL);
            String homeCity = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.HOME_CITY);
            String bio = obj.getJSONObject(FoursquareAuthenticatorConstants.Claim.RESPONSE)
                    .getJSONObject(FoursquareAuthenticatorConstants.Claim.USER)
                    .getString(FoursquareAuthenticatorConstants.Claim.BIO);

            String jsonClaim = "{\"" + FoursquareAuthenticatorConstants.Claim.ID + "\":\"" + id + "\""
                    + ",\"" + FoursquareAuthenticatorConstants.Claim.FIRST_NAME + "\":\"" + fName + "\", \""
                    + FoursquareAuthenticatorConstants.Claim.LAST_NAME + "\":\"" + lName + "\"" + ",\""
                    + FoursquareAuthenticatorConstants.Claim.GENDER + "\":\"" + gender + "\"" + ",\""
                    + FoursquareAuthenticatorConstants.Claim.RELATIONSHIP + "\":\"" + relationship + "\"" + ",\""
                    + FoursquareAuthenticatorConstants.Claim.CANONICAL_URL + "\":\"" + canonicalUrl + "\"" + ",\""
                    + FoursquareAuthenticatorConstants.Claim.HOME_CITY + "\":\"" + homeCity + "\"" + ",\""
                    + FoursquareAuthenticatorConstants.Claim.BIO + "\":\"" + bio + "\"" + ",\""
                    + FoursquareAuthenticatorConstants.Claim.EMAIL + "\":\"" + email + "\"}";

            userClaims = JSONUtils.parseJSON(jsonClaim);

            return userClaims;
        } catch (IOException e) {
            log.error("Exception while sending the request with access token to the use information URL"
                    + e.getMessage(), e);
        } catch (org.json.JSONException e) {
            log.error("Exception while getting the child json object from the json parent object" + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Exception while parsing the string to the json parser" + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Get subject attributes.
     *
     * @param claimMap Map<String, Object>
     * @return
     */
    protected Map<ClaimMapping, String> getSubjectAttributes(Map<String, Object> claimMap) {
        Map<ClaimMapping, String> claims = new HashMap<>();
        if (claimMap != null) {
            for (Map.Entry<String, Object> entry : claimMap.entrySet()) {
                claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false), entry.getValue().toString());
                if (log.isDebugEnabled()) {
                    log.debug("Adding claim from end-point data mapping : "
                            + entry.getKey() + " <> " + " : " + entry.getValue());
                }
            }
        }
        return claims;
    }

}

