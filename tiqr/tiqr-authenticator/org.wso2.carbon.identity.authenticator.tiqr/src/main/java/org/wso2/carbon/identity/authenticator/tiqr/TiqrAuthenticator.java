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

package org.wso2.carbon.identity.authenticator.tiqr;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.String;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.HttpURLConnection;
import java.lang.Integer;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.*;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.authenticator.tiqr.internal.TiqrAuthenticatorServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * Authenticator of Tiqr
 */
public class TiqrAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 1179165995021182755L;
    private static Log log = LogFactory.getLog(TiqrAuthenticator.class);

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
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside TiqrAuthenticator.canHandle()");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(TiqrConstants.TIQR_ACTION))
                && request.getParameter(TiqrConstants.TIQR_ACTION).equals(TiqrConstants.TIQR_ACTION_AUTHENTICATION))
                || (request.getParameter(TiqrConstants.ENROLL_USERID) != null
                && request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME) != null
                && request.getParameter(TiqrConstants.AUTH_USERNAME) != null
                && request.getParameter(TiqrConstants.AUTH_PASSWORD) != null));
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = "&authFailure=true";
                    if (request.getParameter(TiqrConstants.TIQR_ACTION).equals(TiqrConstants.TIQR_ACTION_ENROLLMENT)) {
                        retryParam = retryParam + "&authFailureMsg=enrollment.fail.message";
                    } else {
                        retryParam = retryParam + "&authFailureMsg=authentication.fail.message";
                    }
                }
                String enrollmentPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace(TiqrConstants.LOGIN_PAGE, TiqrConstants.TIQR_PAGE);
                String tiqrAction = StringUtils.isEmpty(request.getParameter(TiqrConstants.TIQR_ACTION))
                        ? TiqrConstants.TIQR_ACTION_AUTHENTICATION : request.getParameter(TiqrConstants.TIQR_ACTION);
                String queryParams = FrameworkUtils
                        .getQueryStringWithFrameworkContextId(context.getQueryParams(),
                                context.getCallerSessionKey(),
                                context.getContextIdentifier());
                response.sendRedirect(response.encodeRedirectURL(enrollmentPage + ("?" + queryParams))
                        + TiqrConstants.AUTHENTICATORS + getName() + ":" + TiqrConstants.LOCAL + "&"
                        + TiqrConstants.TIQR_CLIENT_IP + "=" + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_IP)
                        + "&" + TiqrConstants.TIQR_CLIENT_PORT + "="
                        + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_PORT)
                        + "&" + TiqrConstants.TIQR_ACTION + "=" + tiqrAction + retryParam);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException(
                        "Error while retrieving properties. Authenticator Properties cannot be null");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception while redirecting the page: " + e.getMessage(), e);
        }
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property clientIP = new Property();
        clientIP.setName(TiqrConstants.TIQR_CLIENT_IP);
        clientIP.setDisplayName("Client IP");
        clientIP.setRequired(true);
        clientIP.setDescription("Enter the IP address of the tiqr client");
        configProperties.add(clientIP);

        Property clientPort = new Property();
        clientPort.setName(TiqrConstants.TIQR_CLIENT_PORT);
        clientPort.setDisplayName("Client Port");
        clientPort.setRequired(true);
        clientPort.setDescription("Enter the port of the tiqr client");
        configProperties.add(clientPort);

        Property waitTime = new Property();
        waitTime.setName(TiqrConstants.TIQR_WAIT_TIME);
        waitTime.setDisplayName("Wait Time");
        waitTime.setDescription("Period of waiting to terminate the authentication (in seconds)");
        configProperties.add(waitTime);
        return configProperties;
    }

    /**
     * Process the response of the Tiqr end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            if (request.getParameter(TiqrConstants.TIQR_ACTION).equals(TiqrConstants.TIQR_ACTION_ENROLLMENT)
                    && (StringUtils.isEmpty(request.getParameter(TiqrConstants.ENROLL_USERID))
                    || StringUtils.isEmpty(request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME))
                    || StringUtils.isEmpty(request.getParameter(TiqrConstants.AUTH_USERNAME))
                    || StringUtils.isEmpty(request.getParameter(TiqrConstants.AUTH_PASSWORD)))) {
                log.error("Required fields cannot not be null");
                throw new InvalidCredentialsException();
            } else if (request.getParameter(TiqrConstants.TIQR_ACTION).equals(TiqrConstants.TIQR_ACTION_ENROLLMENT)
                    && StringUtils.isEmpty(request.getParameter(TiqrConstants.ENROLL_SESSIONID))) {
                log.error(TiqrConstants.UNABLE_TO_CONNECT + ":" + TiqrConstants.SESSIONID_NULL);
                throw new AuthenticationFailedException(TiqrConstants.UNABLE_TO_CONNECT + ":" + TiqrConstants.SESSIONID_NULL);
            }
            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            String tiqrEP = getTiqrEndpoint(authenticatorProperties);
            String userId = "";
            int status = 0;
            int retry = 0;
            int retryInterval = 1000;
            int maxCount = 120;
            int waitTime = StringUtils.isEmpty(authenticatorProperties.get(TiqrConstants.TIQR_WAIT_TIME))
                    ? maxCount : Integer.parseInt(authenticatorProperties.get(TiqrConstants.TIQR_WAIT_TIME));
            int retryCount = maxCount > waitTime ? waitTime : maxCount;
            if (request.getParameter(TiqrConstants.TIQR_ACTION).equals(TiqrConstants.TIQR_ACTION_AUTHENTICATION)) {
                String urlToCheckAuthentication = tiqrEP + TiqrConstants.TIQR_CLIENT_AUTHENTICATE_URL
                        + request.getParameter(TiqrConstants.TIQR_CLIENT_AUTH_STATE) + "&"
                        + TiqrConstants.ENROLL_SESSIONID + "=" + request.getParameter(TiqrConstants.ENROLL_SESSIONID);
                while (retry < retryCount) {
                    String checkStatusResponse = sendRESTCall(urlToCheckAuthentication, "",
                            "action=getAuthenticatedUser", TiqrConstants.HTTP_POST);
                    if (checkStatusResponse.startsWith(TiqrConstants.FAILED)) {
                        throw new AuthenticationFailedException("Unable to connect to the Tiqr: "
                                + checkStatusResponse.replace(TiqrConstants.FAILED, ""));
                    }
                    if (checkStatusResponse.contains("authenticatedUser")) {
                        userId = checkStatusResponse.substring(
                                checkStatusResponse.indexOf("name=\"authenticatedUser\" value=\"")
                                , checkStatusResponse.indexOf("\" id=\"authenticatedUser\"/>"))
                                .replace("name=\"authenticatedUser\" value=\"", "").trim();
                        status = StringUtils.isEmpty(userId) ? Integer.parseInt(TiqrConstants.ENROLLMENT_FAILED_STATUS)
                                : Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS);
                        if (status == Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Successfully authenticated the user associated with the User ID:"
                                        + userId);
                            }
                            break;
                        }
                    }
                    Thread.sleep(retryInterval);
                    retry++;
                    if (retry == retryCount) {
                        log.error("Authentication timed out.");
                        break;
                    }
                }
                if (status == Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS)) {
                    String userName = getAssociatedUsername(context, userId);
                    if (StringUtils.isEmpty(userName)) {
                        throw new AuthenticationFailedException("This tiqr user is not associated with " +
                                "any authenticated IS user");
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("The associated username for this Tiqr ID is :" + userName);
                        }
                    }
                }
            } else {
                String username = request.getParameter(TiqrConstants.AUTH_USERNAME);
                String password = request.getParameter(TiqrConstants.AUTH_PASSWORD);
                int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                UserStoreManager userStoreManager = (UserStoreManager) TiqrAuthenticatorServiceComponent.
                        getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
                boolean isAuthenticated = userStoreManager.authenticate(
                        MultitenantUtils.getTenantAwareUsername(username), password);
                if (!isAuthenticated) {
                    log.error(TiqrConstants.INVALID_USERNAME_PASSWORD_ERROR);
                    throw new AuthenticationFailedException(TiqrConstants.INVALID_USERNAME_PASSWORD_ERROR);
                }
                userId = request.getParameter(TiqrConstants.ENROLL_USERID);
                String urlToCheckEntrolment = tiqrEP + TiqrConstants.TIQR_CLIENT_NEW_USER_URL
                        + request.getParameter(TiqrConstants.TIQR_CLIENT_AUTH_STATE) + "&"
                        + TiqrConstants.ENROLL_SESSIONID + "=" + request.getParameter(TiqrConstants.ENROLL_SESSIONID);
                while (retry < retryCount) {
                    String checkStatusResponse = sendRESTCall(urlToCheckEntrolment, "", "action=getStatus"
                            , TiqrConstants.HTTP_POST);
                    if (checkStatusResponse.startsWith(TiqrConstants.FAILED)) {
                        throw new AuthenticationFailedException("Unable to connect to the Tiqr: "
                                + checkStatusResponse.replace(TiqrConstants.FAILED, ""));
                    }
                    if (checkStatusResponse.contains("enrollmentStatus")) {
                        status = Integer.parseInt(checkStatusResponse.substring(
                                checkStatusResponse.indexOf("name=\"enrollmentStatus\" value=\"")
                                , checkStatusResponse.indexOf("\" id=\"enrollmentStatus\"/>"))
                                .replace("name=\"enrollmentStatus\" value=\"", "").trim());
                        if (log.isDebugEnabled()) {
                            log.debug("Enrolment status: " + status);
                        }
                    }
                    if (status == Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully enrolled the user with User ID:"
                                    + request.getParameter(TiqrConstants.ENROLL_USERID)
                                    + "and Display Name:" + request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME));
                        }
                        break;
                    }
                    Thread.sleep(retryInterval);
                    retry++;
                    if (retry == retryCount) {
                        log.error("Enrolment timed out.");
                        break;
                    }
                }
                if (status == Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS)) {
                    associateFederatedIdToLocalUsername(request, context
                            , getFederateAuthenticatedUser(context, userId));
                }
            }
            if (status == Integer.parseInt(TiqrConstants.ENROLLMENT_SUCCESS_STATUS)) {
                setSubject(context, getFederateAuthenticatedUser(context, userId));
            } else {
                throw new AuthenticationFailedException(request.getParameter(TiqrConstants.TIQR_ACTION)
                        + " failed");
            }
        } catch (NumberFormatException e) {
            log.error(request.getParameter(TiqrConstants.TIQR_ACTION) + " failed: " + e.getMessage(), e);
            throw new AuthenticationFailedException(request.getParameter(TiqrConstants.TIQR_ACTION) + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            log.error("Interruption occured while getting the"
                    + request.getParameter(TiqrConstants.TIQR_ACTION) + " status" + e.getMessage(), e);
            throw new AuthenticationFailedException("Interruption occured while getting the"
                    + request.getParameter(TiqrConstants.TIQR_ACTION) + " status" + e.getMessage(), e);
        } catch (IndexOutOfBoundsException e) {
            log.error("Error while getting the "
                    + request.getParameter(TiqrConstants.TIQR_ACTION) + " status" + e.getMessage(), e);
            throw new AuthenticationFailedException("Error while getting the "
                    + request.getParameter(TiqrConstants.TIQR_ACTION) + " status" + e.getMessage(), e);
        } catch (ApplicationAuthenticatorException e) {
            log.error("Unable to set the subject: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Unable to set the subject: " + e.getMessage(), e);
        } catch (UserProfileException e) {
            throw new InvalidCredentialsException();
        } catch (UserStoreException e) {
            log.error("Unable to get the user store manager: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Unable to get the user store manager: " + e.getMessage(), e);
        }
    }

    /**
     * Send REST call
     */
    private String sendRESTCall(String url, String urlParameters, String formParameters, String httpMethod) {
        String line;
        StringBuilder responseString = new StringBuilder();
        HttpURLConnection connection = null;
        try {
            URL tiqrEP = new URL(url + urlParameters);
            connection = (HttpURLConnection) tiqrEP.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(httpMethod);
            connection.setRequestProperty(TiqrConstants.HTTP_CONTENT_TYPE, TiqrConstants.HTTP_CONTENT_TYPE_XWFUE);
            if (httpMethod.toUpperCase().equals(TiqrConstants.HTTP_POST)) {
                OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream(), TiqrConstants.CHARSET);
                writer.write(formParameters);
                writer.close();
            }
            if (connection.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                while ((line = br.readLine()) != null) {
                    responseString.append(line);
                }
                br.close();
            } else {
                return TiqrConstants.FAILED + TiqrConstants.REQUEST_FAILED;
            }
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } finally {
            connection.disconnect();
        }
        return responseString.toString();
    }

    /**
     * Get the tiqr end-point
     */
    protected String getTiqrEndpoint(
            Map<String, String> authenticatorProperties) {
        return TiqrConstants.PROTOCOL + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_IP)
                + ":" + authenticatorProperties.get(TiqrConstants.TIQR_CLIENT_PORT);
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return TiqrConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return TiqrConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    private AuthenticatedUser getFederateAuthenticatedUser(AuthenticationContext context, String authenticatedUserId)
            throws ApplicationAuthenticatorException {
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        authenticatedUser.setUserName(authenticatedUserId);
        if (log.isDebugEnabled()) {
            log.debug("The authenticated subject identifier :" + authenticatedUser.getAuthenticatedSubjectIdentifier());
        }
        return authenticatedUser;
    }

    private void setSubject(AuthenticationContext context, AuthenticatedUser authenticatedUser) {
        context.setSubject(authenticatedUser);
        SequenceConfig seqConfig = context.getSequenceConfig();
        seqConfig.setAuthenticatedUser(authenticatedUser);
    }

    private void associateFederatedIdToLocalUsername(HttpServletRequest request, AuthenticationContext context
            , AuthenticatedUser authenticatedUser)
            throws UserProfileException {
        String authenticatedLocalUsername = request.getParameter(TiqrConstants.AUTH_USERNAME);
        StepConfig stepConfig = null;

        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            stepConfig = context.getSequenceConfig().getStepMap().get(i);
            for (int j = 0; j < stepConfig.getAuthenticatorList().size(); j++) {
                if (stepConfig.getAuthenticatorList().get(j).getName().equals(getName())) {
                    try {
                        String idpName = FrameworkConstants.LOCAL_IDP_NAME;
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

    private String getAssociatedUsername(AuthenticationContext context, String userId) throws UserProfileException {
        StepConfig stepConfig = null;
        String associatedUserName = "";
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            stepConfig = context.getSequenceConfig().getStepMap().get(i);
            for (int j = 0; j < stepConfig.getAuthenticatorList().size(); j++) {
                if (stepConfig.getAuthenticatorList().get(j).getName().equals(getName())) {
                    try {
                        String idpName = FrameworkConstants.LOCAL_IDP_NAME;
                        idpName = context.getExternalIdP().getIdPName();
                        stepConfig.setAuthenticatedIdP(idpName);
                        UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();
                        associatedUserName = userProfileAdmin.getNameAssociatedWith(idpName,
                                userId);
                    } catch (UserProfileException e) {
                        throw new UserProfileException("Unable to get the username associated with " +
                                "the federated ID (" + userId + "): " + e.getMessage(), e);
                    }
                    break;
                }
            }
        }
        return associatedUserName;
    }

    private void associateID(String idpID, String associatedID, String userName) throws UserProfileException {
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
}