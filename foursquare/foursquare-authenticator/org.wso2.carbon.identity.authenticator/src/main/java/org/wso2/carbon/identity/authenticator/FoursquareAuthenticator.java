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

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAuthzResponse;
import org.apache.amber.oauth2.client.response.OAuthClientResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;
import org.apache.amber.oauth2.common.utils.JSONUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.ui.CarbonUIUtil;

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
public class FoursquareAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(FoursquareAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     *
     * @param request the request
     * @return boolean
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside Foursquare OAuth2 Authenticator canHandle");
        }
        return StringUtils.isNotEmpty(request.getParameter(FoursquareAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE))
                && StringUtils.isNotEmpty(request.getParameter(FoursquareAuthenticatorConstants.OAUTH2_PARAM_STATE))
                && FoursquareAuthenticatorConstants.FOURSQUARE_LOGIN_TYPE.equals(getLoginType(request));
    }

    /**
     * Initiate the request and redirect to the authorization URL to get the code
     *
     * @param request  the initial authentication request
     * @param response the response
     * @param context  the application context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String clientId = authenticatorProperties.get(FoursquareAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = getAuthorizationServerEndpoint();
                if (authorizationEP == null) {
                    authorizationEP = authenticatorProperties.get(FoursquareAuthenticatorConstants.OAUTH2_AUTHZ_URL);
                }
                String callbackUrl = CarbonUIUtil.getAdminConsoleURL(request);
                callbackUrl = callbackUrl.replace("commonauth/carbon/", "commonauth");

                String state = context.getContextIdentifier() + ","
                        + FoursquareAuthenticatorConstants.FOURSQUARE_LOGIN_TYPE;

                state = getState(state);

                OAuthClientRequest authorizeRequest;
                authorizeRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callbackUrl)
                        .setResponseType(FoursquareAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state).buildQueryMessage();

                String loginPage = authorizeRequest != null ? authorizeRequest.getLocationUri() : null;

                response.sendRedirect(loginPage);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException(
                        "Error while retrieving properties. Authenticator Properties cannot be null");
            }
        } catch (IOException ioe) {
            log.error("Error while sending to the login page", ioe);
            throw new AuthenticationFailedException(ioe.getMessage(), ioe);
        } catch (OAuthSystemException ose) {
            log.error("Error while building the query message", ose);
            throw new AuthenticationFailedException(ose.getMessage(), ose);
        }
        return;
    }

    /**
     * Get the claim attributes
     *
     * @param claimMap the claim map
     * @return
     */
    protected Map<ClaimMapping, String> getSubjectAttributes(
            Map<String, Object> claimMap) {
        Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();
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

    /**
     * The user claim
     * @param token
     * @return
     */
    private Map<String, Object> getUserClaims(OAuthClientResponse token) {
        Map<String, Object> userClaims;
        try {
            String json = sendRequest(FoursquareAuthenticatorConstants.FOURSQUARE_USER_INFO_ENDPOINT,
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

            String jsonClaim = "{\"" + FoursquareAuthenticatorConstants.Claim.ID + "\":\"" + id + "\""
                    + ",\"" + FoursquareAuthenticatorConstants.Claim.FIRST_NAME + "\":\"" + fName + "\", \""
                    + FoursquareAuthenticatorConstants.Claim.LAST_NAME + "\":\"" + lName + "\""
                    + ",\"" + FoursquareAuthenticatorConstants.Claim.EMAIL + "\":\"" + email + "\"}";

            userClaims = JSONUtils.parseJSON(jsonClaim);

            return userClaims;
        } catch (IOException e) {
            log.error("Exception while sending the request with access token to the use information URL" + e.getMessage(), e);
        } catch (org.json.JSONException e) {
            log.error("Exception while getting the child json object from the json parent object" + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Exception while parsing the string to the json parser" + e.getMessage(), e);
        }
        return null;
    }


    /**
     * Get the configuration properties for the UI
     *
     * @return
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(FoursquareAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Foursquare IDP client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(FoursquareAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Foursquare IDP client secret value");
        configProperties.add(clientSecret);

        return configProperties;
    }

    /**
     * this method are overridden for extra claim request to foursquare end-point
     *
     * @param request  the request
     * @param response the response
     * @param context  the application context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            String clientId = authenticatorProperties
                    .get(FoursquareAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties
                    .get(FoursquareAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint();

            if (tokenEndPoint == null) {
                tokenEndPoint = authenticatorProperties
                        .get(FoursquareAuthenticatorConstants.OAUTH2_TOKEN_URL);
            }

            String callBackUrl = CarbonUIUtil.getAdminConsoleURL(request);
            callBackUrl = callBackUrl.replace("commonauth/carbon/", "commonauth");

            OAuthAuthzResponse authorizeResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authorizeResponse.getCode();

            OAuthClientRequest accessRequest;
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId).setClientSecret(clientSecret)
                    .setRedirectURI(callBackUrl).setCode(code)
                    .buildBodyMessage();

            // create OAuth client that uses custom http client under the hood
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
            String accessToken = oAuthResponse.getParam(FoursquareAuthenticatorConstants.ACCESS_TOKEN);
            if (accessToken != null) {
                Map<String, Object> userClaims = getUserClaims(oAuthResponse);
                if (userClaims != null && !userClaims.isEmpty()) {
                    context.setSubjectAttributes(getSubjectAttributes(userClaims));
                    context.setSubject(userClaims.get(FoursquareAuthenticatorConstants.FOURSQUARE_USER_ID).toString());
                } else {
                    throw new AuthenticationFailedException("Selected user not profile found");//TOOD:change the message
                }
            } else {
                throw new AuthenticationFailedException("Authentication Failed");
            }

        } catch (OAuthProblemException e) {
            log.error("Exception while requesting access token" + e.getMessage(), e);
            throw new AuthenticationFailedException("Exception while requesting access token" + e.getMessage(), e);
        } catch (OAuthSystemException e) {
            log.error("Exception while building the body message" + e.getMessage(), e);
            throw new AuthenticationFailedException("Exception while building the body message" + e.getMessage(), e);
        }
    }

    @Override
    public String getFriendlyName() {
        return FoursquareAuthenticatorConstants.FOURSQUARE_CONNECTOR_FRIENDLY_NAME;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside FoursquareOAuth2Authenticator.getContextIdentifier()");
        }
        String state = request.getParameter(FoursquareAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    @Override
    public String getName() {
        return FoursquareAuthenticatorConstants.FOURSQUARE_CONNECTOR_NAME;
    }

    /**
     * extra request sending to foursquare user info end-point
     *
     * @param url         the endpoint URL
     * @param accessToken the access token
     * @return
     * @throws IOException
     */
    private String sendRequest(String url, String accessToken)
            throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("claim url: " + url + " <> accessToken : " + accessToken);
        }
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

    private String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(FoursquareAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    private String getAuthorizationServerEndpoint() {
        return FoursquareAuthenticatorConstants.FOURSQUARE_OAUTH_ENDPOINT;
    }

    private String getTokenEndpoint() {
        return FoursquareAuthenticatorConstants.FOURSQUARE_TOKEN_ENDPOINT;
    }

    private String getState(String state) {
        return state;
    }

}

