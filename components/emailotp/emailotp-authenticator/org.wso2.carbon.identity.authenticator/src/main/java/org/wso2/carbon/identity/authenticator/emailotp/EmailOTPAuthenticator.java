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

package org.wso2.carbon.identity.authenticator.emailotp;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.mgt.IdentityMgtConfigException;
import org.wso2.carbon.identity.mgt.IdentityMgtServiceException;
import org.wso2.carbon.identity.mgt.NotificationSender;
import org.wso2.carbon.identity.mgt.NotificationSendingModule;
import org.wso2.carbon.identity.mgt.IdentityMgtConfig;
import org.wso2.carbon.identity.mgt.config.Config;
import org.wso2.carbon.identity.mgt.config.ConfigBuilder;
import org.wso2.carbon.identity.mgt.config.ConfigType;
import org.wso2.carbon.identity.mgt.config.StorageType;
import org.wso2.carbon.identity.mgt.dto.NotificationDataDTO;
import org.wso2.carbon.identity.mgt.mail.DefaultEmailSendingModule;
import org.wso2.carbon.identity.mgt.mail.Notification;
import org.wso2.carbon.identity.mgt.mail.NotificationBuilder;
import org.wso2.carbon.identity.mgt.mail.NotificationData;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.axiom.om.util.Base64;
import org.apache.axis2.context.MessageContext;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.InputStream;
import java.lang.String;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Authenticator of EmailOTP
 */
public class EmailOTPAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(EmailOTPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside EmailOTPAuthenticator canHandle method");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE)));
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Properties emailOTPProperties = new Properties();
        String resourceName = EmailOTPAuthenticatorConstants.PROPERTIES_FILE;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        InputStream resourceStream = loader.getResourceAsStream(resourceName);
        try {
            emailOTPProperties.load(resourceStream);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Can not find the file", e);
        }
        if (authenticatorProperties != null) {
            if (!context.isRetrying() || (context.isRetrying()
                    && StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))
                    || (context.isRetrying()
                    && Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))) {
                if (isAccessTokenRequired(emailOTPProperties, authenticatorProperties)) {
                    String tokenResponse = sendTokenRequest(authenticatorProperties);
                    if (tokenResponse.startsWith(EmailOTPAuthenticatorConstants.FAILED)
                            || StringUtils.isEmpty(tokenResponse)) {
                        log.error("Unable to get the access token");
                        throw new AuthenticationFailedException("Unable to get the access token");
                    } else {
                        JSONObject tokenObj = new JSONObject(tokenResponse);
                        String accessToken = tokenObj.getString(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN);
                        context.getAuthenticatorProperties().put(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN
                                , accessToken);
                        authenticatorProperties = context.getAuthenticatorProperties();
                    }
                }
                String username = null;
                String email = null;
                for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
                    if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                            context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {

                        username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                        break;
                    }
                }
                if (StringUtils.isNotEmpty(username)) {
                    UserRealm userRealm = null;
                    try {
                        String tenantDomain = MultitenantUtils.getTenantDomain(username);
                        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                        RealmService realmService = IdentityTenantUtil.getRealmService();
                        userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
                    } catch (Exception e) {
                        throw new AuthenticationFailedException("Cannot find the user realm", e);
                    }
                    username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                    if (userRealm != null) {
                        try {
                            email = userRealm.getUserStoreManager()
                                    .getUserClaimValue(username, EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null).toString();
                            context.setProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL, email);
                        } catch (UserStoreException e) {
                            log.error("Cannot find the user claim for email", e);
                            throw new AuthenticationFailedException("Cannot find the user claim for email " + e.getMessage(), e);
                        }
                    }
                }
                OneTimePassword token = new OneTimePassword();
                String secret = OneTimePassword.getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH);
                String myToken = token.generateToken(secret, "" + EmailOTPAuthenticatorConstants.NUMBER_BASE
                        , EmailOTPAuthenticatorConstants.NUMBER_DIGIT);
                context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, myToken);

                if (StringUtils.isNotEmpty(myToken)) {
                    if (isSMTP(emailOTPProperties, authenticatorProperties)) {
                        sendOTP(username, myToken, email);
                    } else if (StringUtils.isNotEmpty(email)) {
                        String payload = preparePayload(authenticatorProperties, emailOTPProperties, email, myToken);
                        String formData = prepareFormData(authenticatorProperties, emailOTPProperties, email, myToken);
                        String urlParams = prepareURLParams(authenticatorProperties, emailOTPProperties, email, myToken);
                        String sendCodeResponse = sendMailUsingAPIs(authenticatorProperties, emailOTPProperties, urlParams,
                                payload, formData);
                        String failureString = emailOTPProperties.get(getAPI(authenticatorProperties)
                                + EmailOTPAuthenticatorConstants.FAILURE).toString();
                        if (sendCodeResponse.startsWith(EmailOTPAuthenticatorConstants.FAILED)
                                || StringUtils.isEmpty(sendCodeResponse) || sendCodeResponse.contains(failureString)) {
                            log.error("Unable to send the code");
                            throw new AuthenticationFailedException("Unable to send the code");
                        }
                    }
                }
            }
            if (context.isRetrying()
                    || StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
                String emailOTPPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace(EmailOTPAuthenticatorConstants.LOGIN_PAGE, EmailOTPAuthenticatorConstants.EMILOTP_PAGE);
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                        context.getQueryParams(), context.getCallerSessionKey(),
                        context.getContextIdentifier());
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = EmailOTPAuthenticatorConstants.RETRY_PARAMS;
                }
                try {
                    response.sendRedirect(response.encodeRedirectURL(emailOTPPage + ("?" + queryParams))
                            + EmailOTPAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + EmailOTPAuthenticatorConstants.LOCAL
                            + retryParam);
                } catch (IOException e) {
                    log.error("Authentication failed: " + e.getMessage(), e);
                    throw new AuthenticationFailedException(e.getMessage(), e);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
            }
            throw new AuthenticationFailedException(
                    "Error while retrieving properties. Authenticator Properties cannot be null");
        }
    }

    /**
     * Process the response of the EmailOTP end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))) {
            log.error("Code cannot not be null");
            throw new InvalidCredentialsException("Code cannot not be null");
        }
        if (Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
            if (log.isDebugEnabled()) {
                log.debug("Retrying to resend the OTP");
            }
            throw new InvalidCredentialsException("Retrying to resend the OTP");
        }
        String userToken = request.getParameter(EmailOTPAuthenticatorConstants.CODE);
        String contextToken = (String) context.getProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN);
        if (userToken.equals(contextToken)) {
            context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, "");
            context.setProperty(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN, "");
            String emailFromProfile = context.getProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL).toString();
            context.setSubject(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(emailFromProfile));
        } else {
            log.error("Code mismatch");
            throw new AuthenticationFailedException("Code mismatch");
        }
    }

    /**
     * Send REST call
     */
    private String sendRESTCall(String url, String urlParameters, String accessToken, String formParameters
            , String payload, String httpMethod) {
        String line;
        StringBuilder responseString = new StringBuilder();
        HttpURLConnection connection = null;
        try {
            URL emailOTPEP = new URL(url + urlParameters);
            connection = (HttpURLConnection) emailOTPEP.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(httpMethod);
            if (StringUtils.isNotEmpty(payload)) {
                if (payload.startsWith("{")) {
                    connection.setRequestProperty(EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE
                            , payload.startsWith("{") ? EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE_JSON
                            : EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE_XML);
                }
            } else {
                connection.setRequestProperty(EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE
                        , EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE_XWFUE);
            }
            if (StringUtils.isNotEmpty(accessToken)) {
                connection.setRequestProperty(EmailOTPAuthenticatorConstants.HTTP_AUTH, accessToken);
            }
            if (httpMethod.toUpperCase().equals(EmailOTPAuthenticatorConstants.HTTP_POST)) {
                OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream()
                        , EmailOTPAuthenticatorConstants.CHARSET);
                if (StringUtils.isNotEmpty(payload)) {
                    writer.write(payload);
                } else if (StringUtils.isNotEmpty(formParameters)) {
                    writer.write(formParameters);
                }
                writer.close();
            }
            if (connection.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                while ((line = br.readLine()) != null) {
                    responseString.append(line);
                }
                br.close();
            } else {
                return EmailOTPAuthenticatorConstants.FAILED + EmailOTPAuthenticatorConstants.REQUEST_FAILED;
            }
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + e.getMessage());
            }
            return EmailOTPAuthenticatorConstants.FAILED + e.getMessage();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + e.getMessage());
            }
            return EmailOTPAuthenticatorConstants.FAILED + e.getMessage();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + e.getMessage());
            }
            return EmailOTPAuthenticatorConstants.FAILED + e.getMessage();
        } finally {
            connection.disconnect();
        }
        return responseString.toString();
    }

    private String preparePayload(Map<String, String> authenticatorProperties, Properties emailOTPProperties,
                                  String email, String otp) {
        String payload = null;
        if (getAPI(authenticatorProperties).equals(EmailOTPAuthenticatorConstants.API_GMAIL)) {
            payload = "to:" + email + "\n" +
                    "subject:OTP Code\n" +
                    "from:" + authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL) + "\n\n" +
                    otp;
            payload = "{\"raw\":\"" + new String(Base64.encode(payload.getBytes())) + "\"}";
        } else {
            String propertyName = getAPI(authenticatorProperties) + EmailOTPAuthenticatorConstants.PAYLOAD;
            payload = emailOTPProperties.getProperty(propertyName);
            if (StringUtils.isNotEmpty(payload)) {
                String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
                String apiKey = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
            }
        }
        return payload;
    }

    private String prepareURLParams(Map<String, String> authenticatorProperties, Properties emailOTPProperties,
                                    String email, String otp) {
        String propertyName = getAPI(authenticatorProperties) + EmailOTPAuthenticatorConstants.URL_PARAMS;
        return StringUtils.isNotEmpty(emailOTPProperties.getProperty(propertyName))
                ? emailOTPProperties.getProperty(propertyName) : null;
    }

    private String prepareFormData(Map<String, String> authenticatorProperties, Properties emailOTPProperties,
                                   String email, String otp) {
        String propertyName = getAPI(authenticatorProperties) + EmailOTPAuthenticatorConstants.FORM_DATA;
        String formData = emailOTPProperties.getProperty(propertyName);
        if (StringUtils.isNotEmpty(formData)) {
            String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
            String apiKey = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
        }
        return formData;
    }

    private boolean isAccessTokenRequired(Properties emailOTPProperties, Map<String, String> authenticatorProperties) {
        return emailOTPProperties.get(EmailOTPAuthenticatorConstants.ACCESS_TOKEN_REQUIRED_APIS).toString()
                .contains(getAPI(authenticatorProperties));
    }

    private boolean isAPIKeyHeaderRequired(Properties emailOTPProperties, Map<String, String> authenticatorProperties) {
        return emailOTPProperties.get(EmailOTPAuthenticatorConstants.API_KEY_HEADER_REQUIRED_APIS).toString()
                .contains(getAPI(authenticatorProperties));
    }

    private String getAPI(Map<String, String> authenticatorProperties) {
        String api = null;
        if (authenticatorProperties.get(EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)
                .contains(EmailOTPAuthenticatorConstants.GMAIL_HOST)) {
            api = EmailOTPAuthenticatorConstants.API_GMAIL;
        } else if (authenticatorProperties.get(EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)
                .contains(EmailOTPAuthenticatorConstants.MANDRILL_HOST)) {
            api = EmailOTPAuthenticatorConstants.API_MANDRILL;
        } else if (authenticatorProperties.get(EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)
                .contains(EmailOTPAuthenticatorConstants.SENDGRID_HOST)) {
            api = EmailOTPAuthenticatorConstants.API_SENDGRID;
        }
        return api;
    }

    private String sendMailUsingAPIs(Map<String, String> authenticatorProperties, Properties emailOTPProperties, String urlParams,
                                     String payload, String formData) {
        String response = null;
        if ((isAccessTokenRequired(emailOTPProperties, authenticatorProperties)
                && StringUtils.isEmpty(authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN)))
                || (isAPIKeyHeaderRequired(emailOTPProperties, authenticatorProperties)
                && StringUtils.isEmpty(authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)))) {
            log.error("Required param '" + (isAccessTokenRequired(emailOTPProperties, authenticatorProperties)
                    ? EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN
                    : EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY) + "' cannot be null");
            return null;
        } else if (isAccessTokenRequired(emailOTPProperties, authenticatorProperties)
                || isAPIKeyHeaderRequired(emailOTPProperties, authenticatorProperties)) {
            response = sendRESTCall(
                    authenticatorProperties.get(EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)
                            .replace(EmailOTPAuthenticatorConstants.ADMIN_EMAIL
                                    , authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL))
                    , StringUtils.isNotEmpty(urlParams) ? urlParams : ""
                    , emailOTPProperties.get(getAPI(authenticatorProperties)
                            + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE) + " "
                            + (isAccessTokenRequired(emailOTPProperties, authenticatorProperties)
                            ? authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN)
                            : authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)), formData
                    , payload, EmailOTPAuthenticatorConstants.HTTP_POST);
        } else {
            response = sendRESTCall(
                    authenticatorProperties.get(EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)
                    , StringUtils.isNotEmpty(urlParams) ? urlParams : "", "", "", payload,
                    EmailOTPAuthenticatorConstants.HTTP_POST);
        }
        return response;
    }

    private String sendTokenRequest(Map<String, String> authenticatorProperties) {
        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String refreshToken = authenticatorProperties.get(EmailOTPAuthenticatorConstants.REFRESH_TOKEN);
        String response = null;
        if (StringUtils.isNotEmpty(clientId) && StringUtils.isNotEmpty(clientSecret)
                && StringUtils.isNotEmpty(refreshToken)) {
            String formParams = EmailOTPAuthenticatorConstants.EMAILOTP_CLIENT_SECRET + "=" + clientSecret
                    + "&" + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE + "="
                    + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE_REFRESH_TOKEN + "&"
                    + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE_REFRESH_TOKEN + "=" + refreshToken
                    + "&" + EmailOTPAuthenticatorConstants.EMAILOTP_CLIENT_ID + "=" + clientId;
            response = sendRESTCall(getTokenEndpoint(authenticatorProperties), "", "", formParams, ""
                    , EmailOTPAuthenticatorConstants.HTTP_POST);
        } else {
            log.error("Required params cannot be null");
            return null;
        }
        return response;
    }

    /**
     * Get EmailOTP token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        Properties emailOTPProperties = new Properties();
        String resourceName = EmailOTPAuthenticatorConstants.PROPERTIES_FILE;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        InputStream resourceStream = loader.getResourceAsStream(resourceName);
        try {
            emailOTPProperties.load(resourceStream);
        } catch (IOException e) {
            log.error("Can not find the file", e);
        }
        String tokenEndpoint = emailOTPProperties.get(getAPI(authenticatorProperties)
                + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT).toString();
        return StringUtils.isNotEmpty(tokenEndpoint) ? tokenEndpoint : null;
    }

    private void sendOTP(String username, String otp, String email) throws AuthenticationFailedException {
        NotificationSender notificationSender = new NotificationSender();
        NotificationDataDTO notificationData = new NotificationDataDTO();
        Notification emailNotification = null;
        NotificationData emailNotificationData = new NotificationData();
        ConfigBuilder configBuilder = ConfigBuilder.getInstance();
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        String emailTemplate;
        Config config;

        if (MessageContext.getCurrentMessageContext() != null &&
                MessageContext.getCurrentMessageContext().getProperty(
                        MessageContext.TRANSPORT_HEADERS) != null) {
            notificationData.setTransportHeaders(new HashMap(
                    (Map) MessageContext.getCurrentMessageContext().getProperty(
                            MessageContext.TRANSPORT_HEADERS)));
        }

        try {
            config = configBuilder.loadConfiguration(ConfigType.EMAIL,
                    StorageType.REGISTRY, tenantId);
        } catch (IdentityMgtConfigException e) {
            log.error("Error occurred while loading email templates for user : " + username, e);
            throw new AuthenticationFailedException("Error occurred while loading email templates for user : "
                    + username, e);
        }

        emailNotificationData.setTagData(EmailOTPAuthenticatorConstants.CODE, otp);
        emailNotificationData.setSendTo(email);
        emailTemplate = config.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        try {
            emailNotification = NotificationBuilder.createNotification("EMAIL", emailTemplate, emailNotificationData);
        } catch (IdentityMgtServiceException e) {
            log.error("Error occurred while creating notification from email template : " + emailTemplate, e);
            throw new AuthenticationFailedException("Error occurred while creating notification from email template : "
                    + emailTemplate, e);
        }
        notificationData.setNotificationAddress(email);
        NotificationSendingModule module = new DefaultEmailSendingModule();

        if (IdentityMgtConfig.getInstance().isNotificationInternallyManaged()) {
            module.setNotificationData(notificationData);
            module.setNotification(emailNotification);
            notificationSender.sendNotification(module);
            notificationData.setNotificationSent(true);
        } else {
            notificationData.setNotificationSent(false);
            notificationData.setNotificationCode(otp);
        }
    }

    private boolean isSMTP(Properties emailOTPProperties, Map<String, String> authenticatorProperties) {
        String mailingEndpoint = authenticatorProperties.get(EmailOTPAuthenticatorConstants.MAILING_ENDPOINT);
        String apiKey = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
        String refreshToken = authenticatorProperties.get(EmailOTPAuthenticatorConstants.REFRESH_TOKEN);
        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String email = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
        if (StringUtils.isEmpty(email) || StringUtils.isEmpty(mailingEndpoint)
                || (!isAccessTokenRequired(emailOTPProperties, authenticatorProperties) && StringUtils.isEmpty(apiKey))
                || (isAccessTokenRequired(emailOTPProperties, authenticatorProperties)
                && (StringUtils.isEmpty(refreshToken) || StringUtils.isEmpty(clientId)
                || StringUtils.isEmpty(clientSecret)))) {
            return true;
        }
        return false;
    }

    /**
     * Check ID token in EmailOTP OAuth.
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
        return EmailOTPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
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
        clientId.setDescription("Enter client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        clientSecret.setDisplayOrder(1);
        configProperties.add(clientSecret);

        Property email = new Property();
        email.setName(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
        email.setDisplayName("Email");
        email.setDescription("Email address of the sender");
        email.setDisplayOrder(2);
        configProperties.add(email);

        Property apiKey = new Property();
        apiKey.setName(EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
        apiKey.setDisplayName("API key");
        apiKey.setConfidential(true);
        apiKey.setDescription("Enter API key");
        apiKey.setDisplayOrder(3);
        configProperties.add(apiKey);

        Property refreshToken = new Property();
        refreshToken.setDisplayName("Refresh Token");
        refreshToken.setName(EmailOTPAuthenticatorConstants.REFRESH_TOKEN);
        refreshToken.setDescription("Enter the refreshToken to refress the access token");
        refreshToken.setDisplayOrder(4);
        configProperties.add(refreshToken);

        Property endpoint = new Property();
        endpoint.setDisplayName("Email Endpoint");
        endpoint.setName(EmailOTPAuthenticatorConstants.MAILING_ENDPOINT);
        endpoint.setDescription("Give the API method endpoint to send email" +
                "(E.g:- for gmail: https://www.googleapis.com/gmail/v1/users/[userId]/messages/send)");
        endpoint.setDisplayOrder(5);
        configProperties.add(endpoint);
        return configProperties;
    }
}