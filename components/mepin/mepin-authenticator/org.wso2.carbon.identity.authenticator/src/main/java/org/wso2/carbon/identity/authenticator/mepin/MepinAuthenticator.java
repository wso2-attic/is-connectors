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

package org.wso2.carbon.identity.authenticator.mepin;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.mepin.internal.MepinAuthenticatorServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of MePIN
 */
public class MepinAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -8948601002969608129L;
    private static Log log = LogFactory.getLog(MepinAuthenticator.class);
    private Map<String, String> authenticatorProperties;

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside MepinAuthenticator.canHandle()");
        }
        return ((!StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN)))
                || (!StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_LOGIN))));

    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        authenticatorProperties = context.getAuthenticatorProperties();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace(MepinConstants.LOGIN_PAGE,
                                                                                                    MepinConstants.MEPIN_PAGE);
        boolean isSecondStep = false;
        try {
            String authenticatedLocalUsername = getLocalAuthenticatedUser(context).getUserName();
            if (StringUtils.isNotEmpty(authenticatedLocalUsername)) {
                isSecondStep = true;
            }
        } catch (NullPointerException e) {
            log.warn("Username cannot be fetched from previous authentication steps.");
        }

        try {
            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=authentication.fail.message";
            }
            response.sendRedirect(response.encodeRedirectURL(loginPage + "?authenticators=" + getName()
                                                             + "&applicationId=" + authenticatorProperties.get(MepinConstants.MEPIN_APPICATION_ID)
                                                             + "&callbackUrl=" + authenticatorProperties.get(MepinConstants.MEPIN_CALLBACK_URL)
                                                             + "&" + FrameworkConstants.SESSION_DATA_KEY + "=" + context.getContextIdentifier()
                                                             + "&isSecondStep=" + isSecondStep + retryParam));
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while redirecting");
            }
            throw new AuthenticationFailedException("Error while redirecting the MePIN");
        }
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property applicationId = new Property();
        applicationId.setName(MepinConstants.MEPIN_APPICATION_ID);
        applicationId.setDisplayName("Application Id");
        applicationId.setRequired(true);
        applicationId.setDescription("Enter MePIN application id value");
        applicationId.setDisplayOrder(1);
        configProperties.add(applicationId);

        Property username = new Property();
        username.setName(MepinConstants.MEPIN_USERNAME);
        username.setDisplayName("Username");
        username.setRequired(true);
        username.setDescription("Enter username");
        username.setDisplayOrder(2);
        configProperties.add(username);

        Property password = new Property();
        password.setName(MepinConstants.MEPIN_PASSWORD);
        password.setDisplayName("Password");
        password.setRequired(true);
        password.setConfidential(true);
        password.setDescription("Enter password");
        password.setDisplayOrder(3);
        configProperties.add(password);

        Property callbackUrl = new Property();
        callbackUrl.setName(MepinConstants.MEPIN_CALLBACK_URL);
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter value corresponding to callback url");
        callbackUrl.setDisplayOrder(4);
        configProperties.add(callbackUrl);

        Property clientId = new Property();
        clientId.setName(MepinConstants.MEPIN_CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Client Id");
        clientId.setDisplayOrder(5);
        configProperties.add(clientId);

        Property confirmationPolicy = new Property();
        confirmationPolicy.setName(MepinConstants.MEPIN_CONFIRMATION_POLICY);
        confirmationPolicy.setDisplayName("Confirmation Policy");
        confirmationPolicy.setRequired(true);
        confirmationPolicy.setDescription("Enter Confirmation Policy (tap, pin, swipe, fp)");
        confirmationPolicy.setDisplayOrder(6);
        configProperties.add(confirmationPolicy);

        Property expiryTime = new Property();
        expiryTime.setName(MepinConstants.MEPIN_EXPIRY_TIME);
        expiryTime.setDisplayName("Expiry Time");
        expiryTime.setRequired(true);
        expiryTime.setDescription("Enter Expiry Time (in seconds)");
        expiryTime.setDisplayOrder(7);
        configProperties.add(expiryTime);

        Property header = new Property();
        header.setName(MepinConstants.MEPIN_HEADER);
        header.setDisplayName("Header");
        header.setRequired(true);
        header.setDescription("Enter Header");
        header.setDisplayOrder(8);
        configProperties.add(header);

        Property message = new Property();
        message.setName(MepinConstants.MEPIN_MESSAGE);
        message.setDisplayName("Message");
        message.setRequired(true);
        message.setDescription("Enter Message");
        message.setDisplayOrder(9);
        configProperties.add(message);

        Property shortMessage = new Property();
        shortMessage.setName(MepinConstants.MEPIN_SHORT_MESSAGE);
        shortMessage.setDisplayName("Short Message");
        shortMessage.setRequired(true);
        shortMessage.setDescription("Enter Short Message");
        shortMessage.setDisplayOrder(10);
        configProperties.add(shortMessage);

        return configProperties;
    }

    /**
     * Process the response of the MePIN end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        String username;
        String password;
        if ((!StringUtils.isEmpty(request.getParameter(MepinConstants.IS_SECOND_STEP))
             && !StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN)))) {

            if (request.getParameter(MepinConstants.IS_SECOND_STEP).equals(MepinConstants.TRUE)) {
                username = getLocalAuthenticatedUser(context).getUserName();
            } else {
                String authHeader = request.getParameter(MepinConstants.AUTH_HEADER);
                UserStoreManager userStoreManager = null;
                authHeader = new String(Base64.decodeBase64(authHeader.getBytes()));
                int index = authHeader.indexOf(":");
                username = authHeader.substring(0, index);
                password = authHeader.substring(index + 1, authHeader.length());
                int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                try {
                    userStoreManager = (UserStoreManager) MepinAuthenticatorServiceComponent.
                            getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
                    boolean isAuthenticated = false;
                    isAuthenticated = userStoreManager.authenticate(
                            MultitenantUtils.getTenantAwareUsername(username), password);
                    if (!isAuthenticated) {
                        throw new AuthenticationFailedException("Authentication Failed: Invalid username or password");
                    }
                } catch (UserStoreException e) {
                    log.error("Unable to get the user store manager: " + e.getMessage(), e);
                    throw new AuthenticationFailedException("Unable to get the user store manager: " + e.getMessage(), e);
                }
            }

            try {
                String accessToken = request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN);
                String responseString = new MepinTransactions().getUserInformation(authenticatorProperties.get(MepinConstants.MEPIN_USERNAME),
                                                                                   authenticatorProperties.get(MepinConstants.MEPIN_PASSWORD),
                                                                                   accessToken);
                if (!responseString.equals(MepinConstants.FAILED)) {
                    JsonObject responseJson = new JsonParser().parse(responseString).getAsJsonObject();
                    String mepinId = responseJson.getAsJsonPrimitive(MepinConstants.MEPIN_ID).getAsString();
                    associateFederatedIdToLocalUsername(username, context, getFederateAuthenticatedUser(context, mepinId));
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                } else {
                    throw new AuthenticationFailedException("Unable to get the MePIN ID.");
                }
            } catch (ApplicationAuthenticatorException e) {
                log.error("Unable to set the subject: " + e.getMessage(), e);
                throw new AuthenticationFailedException("Unable to set the subject: " + e.getMessage(), e);
            } catch (UserProfileException e) {
                log.error("Unable to associate the user: " + e.getMessage(), e);
                throw new AuthenticationFailedException("Unable to associate the user: " + e.getMessage(), e);
            }

        } else {

            if (request.getParameter(MepinConstants.IS_SECOND_STEP).equals(MepinConstants.TRUE)) {
                username = getLocalAuthenticatedUser(context).getUserName();
            } else {
                username = request.getParameter(MepinConstants.USERNAME);
                password = request.getParameter(MepinConstants.PASSWORD);
                boolean isBasicAuthenticated = false;
                UserStoreManager userStoreManager = null;
                int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                try {
                    userStoreManager = (UserStoreManager) MepinAuthenticatorServiceComponent.
                            getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
                    isBasicAuthenticated = userStoreManager.authenticate(
                            MultitenantUtils.getTenantAwareUsername(username), password);
                    if (!isBasicAuthenticated) {
                        throw new AuthenticationFailedException("Authentication Failed: Invalid username or password");
                    }
                } catch (UserStoreException e) {
                    log.error("Unable to get the user store manager: " + e.getMessage(), e);
                    throw new AuthenticationFailedException("Unable to get the user store manager: " + e.getMessage(), e);
                }


            }
            String allowStatus = "";

            try {

                String idpName = context.getExternalIdP().getIdPName();
                String mePinId = null;
                mePinId = getMepinIdAssociatedWithUsername(idpName, username);
                boolean isAuthenticated = false;
                String transactionResponseString = new MepinTransactions().createTransaction(mePinId, context.getContextIdentifier(),
                                                                                             MepinConstants.MEPIN_CREATE_TRANSACTION_URL,
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_USERNAME),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_PASSWORD),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_CLIENT_ID),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_HEADER),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_MESSAGE),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_SHORT_MESSAGE),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_CONFIRMATION_POLICY),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_CALLBACK_URL),
                                                                                             authenticatorProperties.get(MepinConstants.MEPIN_EXPIRY_TIME));
                if (!transactionResponseString.equals(MepinConstants.FAILED)) {
                    JsonObject transactionResponseJson = new JsonParser().parse(transactionResponseString).getAsJsonObject();
                    String transactionId = transactionResponseJson.getAsJsonPrimitive(MepinConstants.MEPIN_TRANSACTION_ID).getAsString();
                    String status = transactionResponseJson.getAsJsonPrimitive(MepinConstants.MEPIN_STATUS).getAsString();
                    if (status.equalsIgnoreCase(MepinConstants.MEPIN_OK)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully created the MePIN transaction");
                        }
                        int retry = 0;
                        int retryInterval = 1;
                        int retryCount = Integer.parseInt(authenticatorProperties.get(MepinConstants.MEPIN_EXPIRY_TIME)) / retryInterval;
                        while (retry < retryCount) {
                            String responseString = new MepinTransactions().getTransaction(MepinConstants.MEPIN_GET_TRANSACTION_URL,
                                                                                           transactionId, authenticatorProperties.get(MepinConstants.MEPIN_CLIENT_ID),
                                                                                           authenticatorProperties.get(MepinConstants.MEPIN_USERNAME),
                                                                                           authenticatorProperties.get(MepinConstants.MEPIN_PASSWORD));
                            if (!responseString.equals(MepinConstants.FAILED)) {
                                JsonObject transactionStatusResponse = new JsonParser().parse(responseString).getAsJsonObject();
                                String transactionStatus = transactionStatusResponse.getAsJsonPrimitive(MepinConstants.MEPIN_TRANSACTION_STATUS).getAsString();
                                JsonPrimitive allowObject = transactionStatusResponse.getAsJsonPrimitive(MepinConstants.MEPIN_ALLOW);
                                if (log.isDebugEnabled()) {
                                    log.debug("Transaction status :" + transactionStatus);
                                }
                                if (transactionStatus.equals(MepinConstants.MEPIN_COMPLETED)) {
                                    allowStatus = allowObject.getAsString();
                                    if (Boolean.parseBoolean(allowStatus)) {
                                        isAuthenticated = true;
                                        break;
                                    }
                                } else if (transactionStatus.equals(MepinConstants.MEPIN_CANCELED) || transactionStatus.equals(MepinConstants.MEPIN_EXPIRED)
                                           || transactionStatus.equals(MepinConstants.MEPIN_ERROR)) {
                                    break;
                                }
                            }
                            Thread.sleep(1000);
                            retry++;
                        }
                        if (isAuthenticated) {
                            context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                        } else {
                            throw new AuthenticationFailedException("Unable to confirm the MePIN transaction");
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Error while creating the MePIN transaction");
                        }
                        throw new AuthenticationFailedException("Error while creating the MePIN transaction");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while creating the MePIN transaction");
                    }
                    throw new AuthenticationFailedException("Error while creating the MePIN transaction");
                }
            } catch (UserProfileException e) {
                log.error("Unable to get the associated user: " + e.getMessage(), e);
                throw new AuthenticationFailedException("Unable to get the associated user: " + e.getMessage(), e);
            } catch (IOException e) {
                log.error("Unable to create the MePIN transaction: " + e.getMessage(), e);
                throw new AuthenticationFailedException("Unable to create the MePIN transaction: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                log.error("Interruption occurred while getting the MePIN transaction status" + e.getMessage(), e);
                throw new AuthenticationFailedException("Interruption occurred while getting the MePIN transaction status" + e.getMessage(), e);
            }
        }
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return MepinConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return MepinConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        return super.process(request, response, context);
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }


    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    private AuthenticatedUser getLocalAuthenticatedUser(AuthenticationContext context) {
        //Getting the last authenticated local user
        AuthenticatedUser authenticatedUser = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                        .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser();
                break;
            }
        }

        return authenticatedUser;
    }

    private AuthenticatedUser getFederateAuthenticatedUser(AuthenticationContext context,
                                                           String authenticatedUserId)
            throws ApplicationAuthenticatorException {
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        if (authenticatedUser.getUserStoreDomain() == null) {
            authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        }
        authenticatedUser.setUserName(authenticatedUserId);
        if (log.isDebugEnabled()) {
            log.debug("The authenticated subject identifier :" + authenticatedUser.getAuthenticatedSubjectIdentifier());
        }
        return authenticatedUser;
    }

    private void associateFederatedIdToLocalUsername(String authenticatedLocalUsername,
                                                     AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser)
            throws UserProfileException {
        StepConfig stepConfig = null;

        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            stepConfig = context.getSequenceConfig().getStepMap().get(i);
            for (int j = 0; j < stepConfig.getAuthenticatorList().size(); j++) {
                if (stepConfig.getAuthenticatorList().get(j).getName().equals(getName())) {
                    try {
                        String idpName;
                        String originalExternalIdpSubjectValueForThisStep =
                                authenticatedUser.getAuthenticatedSubjectIdentifier();
                        idpName = context.getExternalIdP().getIdPName();
                        stepConfig.setAuthenticatedIdP(idpName);
                        associateID(idpName,
                                    originalExternalIdpSubjectValueForThisStep, authenticatedLocalUsername);
                        stepConfig.setAuthenticatedUser(authenticatedUser);
                        context.getSequenceConfig().getStepMap().put(i, stepConfig);
                    } catch (UserProfileException e) {
                        throw new UserProfileException("Unable to continue with the federated ID ("
                                                       + authenticatedUser.getAuthenticatedSubjectIdentifier() + "): " + e.getMessage(), e);
                    }
                    break;
                }
            }
        }
    }

    private void associateID(String idpID, String associatedID, String userName)
            throws UserProfileException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String sql = null;
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
        String domainName = getDomainName(tenantAwareUsername);
        tenantAwareUsername = getUsernameWithoutDomain(tenantAwareUsername);

        try {
            sql = "INSERT INTO IDN_ASSOCIATED_ID (TENANT_ID, IDP_ID, IDP_USER_ID, DOMAIN_NAME, USER_NAME) VALUES " +
                  "(? , (SELECT ID FROM IDP WHERE NAME = ? AND TENANT_ID = ? ), ? , ?, ?)";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpID);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, associatedID);
            prepStmt.setString(5, domainName);
            prepStmt.setString(6, tenantAwareUsername);
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            log.error("Error occurred while persisting the federated user ID", e);
            throw new UserProfileException("Error occurred while persisting the federated user ID", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, (ResultSet) null, prepStmt);
        }
    }

    private static String getDomainName(String username) {
        int index = username.indexOf("/");
        return index < 0 ? "PRIMARY" : username.substring(0, index);
    }

    private static String getUsernameWithoutDomain(String username) {
        int index = username.indexOf("/");
        return index < 0 ? username : username.substring(index + 1, username.length());
    }

    public String getMepinIdAssociatedWithUsername(String idpID, String username)
            throws UserProfileException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = null;
        String mepinId = "";
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        try {
            sql = "SELECT IDP_USER_ID  FROM IDN_ASSOCIATED_ID WHERE TENANT_ID = ? AND IDP_ID = (SELECT ID " +
                  "FROM IDP WHERE NAME = ? AND TENANT_ID = ?) AND USER_NAME = ?";

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpID);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, username);

            resultSet = prepStmt.executeQuery();
            connection.commit();

            if (resultSet.next()) {
                mepinId = resultSet.getString(1);
                return mepinId;
            }

        } catch (SQLException e) {
            log.error("Error occurred while getting the associated MePIN ID", e);
            throw new UserProfileException("Error occurred while getting the associated MePIN ID", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return null;
    }
}