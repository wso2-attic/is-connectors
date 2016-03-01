/*
 *  Copyright (c) 2015-2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.provisioning.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.identity.provisioning.ProvisionedIdentifier;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;

import java.util.Properties;

public class InweboProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final Log log = LogFactory.getLog(InweboProvisioningConnector.class);
    private InweboProvisioningConnectorConfig configHolder;

    @Override
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        Properties configs = new Properties();

        if (provisioningProperties != null && provisioningProperties.length > 0) {
            for (Property property : provisioningProperties) {
                configs.put(property.getName(), property.getValue());
                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property
                        .getName())) {
                    if ("1".equals(property.getValue())) {
                        jitProvisioningEnabled = true;
                    }
                }
            }
        }
        configHolder = new InweboProvisioningConnectorConfig(configs);
    }

    @Override
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {
        try {
            String provisionedId = null;
            if (provisioningEntity != null) {
                String login = provisioningEntity.getEntityName().toString();
                String userId = configHolder.getValue(InweboConnectorConstants.INWEBO_USER_ID);
                String serviceId = configHolder.getValue(InweboConnectorConstants.INWEBO_SERVICE_ID);
                String p12file = configHolder.getValue(InweboConnectorConstants.INWEBO_P12FILE);
                String p12password = configHolder.getValue(InweboConnectorConstants.INWEBO_P12PASSWORD);
                String status = configHolder.getValue(InweboConnectorConstants.INWEBO_STATUS);
                String role = configHolder.getValue(InweboConnectorConstants.INWEBO_ROLE);
                String access = configHolder.getValue(InweboConnectorConstants.INWEBO_ACCESS);
                String codeType = configHolder.getValue(InweboConnectorConstants.INWEBO_CODETYPE);
                String extraFields = StringUtils.isNotEmpty(configHolder.getValue(InweboConnectorConstants.INWEBO_EXTRAFIELDS))
                        ? configHolder.getValue(InweboConnectorConstants.INWEBO_EXTRAFIELDS) : "";
                String language = StringUtils.isNotEmpty(configHolder.getValue(InweboConnectorConstants.INWEBO_LANG))
                        ? configHolder.getValue(InweboConnectorConstants.INWEBO_LANG)
                        : InweboConnectorConstants.INWEBO_LANG_ENGLISH;

                String firstNameClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.InweboConnectorClaims.FIRST_NAME_CLAIM,
                                InweboConnectorConstants.InweboConnectorClaims.IDP_CLAIM_URI_FIRSTNAME,
                                (String) null, false)).get(0);
                String lastNameClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.InweboConnectorClaims.LAST_NAME_CLAIM,
                                InweboConnectorConstants.InweboConnectorClaims.IDP_CLAIM_URI_LARSTNAME,
                                (String) null, false)).get(0);
                String emailClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.InweboConnectorClaims.MAIL_CLAIM,
                                InweboConnectorConstants.InweboConnectorClaims.IDP_CLAIM_URI_EMAIL,
                                (String) null, false)).get(0);
                String phoneClaim = provisioningEntity.getAttributes().get(ClaimMapping
                        .build(InweboConnectorConstants.InweboConnectorClaims.PHONE_CLAIM,
                                InweboConnectorConstants.InweboConnectorClaims.IDP_CLAIM_URI_PHONE,
                                (String) null, false)).get(0);

                String firstName = StringUtils.isNotEmpty(firstNameClaim) ? firstNameClaim : "";
                String name = StringUtils.isNotEmpty(lastNameClaim) ? lastNameClaim : "";
                String mail = StringUtils.isNotEmpty(emailClaim) ? emailClaim : "";
                String phone = StringUtils.isNotEmpty(phoneClaim) ? phoneClaim : "";


                if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("JIT provisioning disabled for inwebo connector");
                    }
                    return null;
                }
                if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                    System.setProperty(InweboConnectorConstants.AXIS2, InweboConnectorConstants.AXIS2_FILE);
                    if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                        provisionedId = createUser(provisioningEntity, userId, serviceId, login, firstName,
                                name, mail, phone, status, role, access, codeType, language, extraFields, p12file, p12password);
                        if (StringUtils.isNotEmpty(provisionedId) && !provisionedId.equals("0")) {
                            log.info("User creation in InWebo is done.");
                        }
                    } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                        String loginFromClaim = provisioningEntity.getAttributes().get(ClaimMapping
                                .build(InweboConnectorConstants.InweboConnectorClaims.USERNAME_CLAIM, null,
                                        (String) null, false)).get(0);
                        String firstNameFromClaim = provisioningEntity.getAttributes().get(ClaimMapping
                                .build(InweboConnectorConstants.InweboConnectorClaims.FIRST_NAME_CLAIM,
                                        InweboConnectorConstants.InweboConnectorClaims.FIRST_NAME_CLAIM,
                                        (String) null, false)).get(0);
                        String nameFromClaim = provisioningEntity.getAttributes().get(ClaimMapping
                                .build(InweboConnectorConstants.InweboConnectorClaims.LAST_NAME_CLAIM,
                                        InweboConnectorConstants.InweboConnectorClaims.LAST_NAME_CLAIM,
                                        (String) null, false)).get(0);
                        String mailFromClaim = provisioningEntity.getAttributes().get(ClaimMapping
                                .build(InweboConnectorConstants.InweboConnectorClaims.MAIL_CLAIM,
                                        InweboConnectorConstants.InweboConnectorClaims.MAIL_CLAIM,
                                        (String) null, false)).get(0);
                        String phoneFromClaim = provisioningEntity.getAttributes().get(ClaimMapping
                                .build(InweboConnectorConstants.InweboConnectorClaims.PHONE_CLAIM,
                                        InweboConnectorConstants.InweboConnectorClaims.PHONE_CLAIM,
                                        (String) null, false)).get(0);

                        login = StringUtils.isNotEmpty(loginFromClaim) ? loginFromClaim : login;
                        firstName = StringUtils.isNotEmpty(firstNameFromClaim) ? firstNameFromClaim : firstName;
                        name = StringUtils.isNotEmpty(nameFromClaim) ? nameFromClaim : name;
                        mail = StringUtils.isNotEmpty(mailFromClaim) ? mailFromClaim : mail;
                        phone = StringUtils.isNotEmpty(phoneFromClaim) ? phoneFromClaim : phone;

                        updateUser(provisioningEntity, userId, serviceId, login, firstName, name, mail, phone, status,
                                role, extraFields, p12file, p12password);
                    } else if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                        deleteUser(provisioningEntity, serviceId, userId, p12file, p12password);
                    } else {
                        throw new IdentityProvisioningException("Unsupported provisioning opertaion.");
                    }
                } else {
                    throw new IdentityProvisioningException("Unsupported provisioning opertaion.");
                }
            }
            // creates a provisioned identifier for the provisioned user.
            ProvisionedIdentifier identifier = new ProvisionedIdentifier();
            if (StringUtils.isNotEmpty(provisionedId) && !provisionedId.equals("0")) {
                identifier.setIdentifier(provisionedId);
            }
            return identifier;
        } catch (IdentityProvisioningException e) {
            log.error(e);
            return null;
        }
    }

    private String createUser(ProvisioningEntity provisioningEntity, String userId, String serviceId, String login,
                              String firstName, String name, String mail, String phone, String status, String role,
                              String access, String codeType,
                              String language, String extraFields, String p12file, String p12password)
            throws IdentityProvisioningException {
        String provisionedId = null;
        try {
            Util.setHttpsClientCert(p12file, p12password);
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while adding certificate", e);

        }
        try {
            UserCreation userCreation = new UserCreation();
            provisionedId = userCreation.invokeSOAP(userId, serviceId, login, firstName, name, mail, phone, status,
                    role, access, codeType, language, extraFields);
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while creating the user in InWebo:", e);
        }
        return provisionedId;
    }

    private void updateUser(ProvisioningEntity provisioningEntity, String userId, String serviceId,
                            String login, String firstName, String name, String mail, String phone, String status,
                            String role, String extraFields, String p12file, String p12password)
            throws IdentityProvisioningException {
        boolean updationStatus = false;
        try {
            Util.setHttpsClientCert(p12file, p12password);
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while adding certificate", e);

        }
        try {
            String loginId = provisioningEntity.getIdentifier().getIdentifier();
            UserUpdation userUpdation = new UserUpdation();
            userUpdation.invokeSOAP(userId, serviceId, loginId, login, firstName, name, mail,
                    phone, status, role, extraFields);
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while updating the user", e);
        }
    }

    /**
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity provisioningEntity, String serviceId, String userId, String p12file, String p12password)
            throws IdentityProvisioningException {
        boolean deletionStatus = false;
        try {
            Util.setHttpsClientCert(p12file, p12password);
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while adding certificate", e);
        }
        try {
            String loginId = provisioningEntity.getIdentifier().getIdentifier();
            UserDeletion UserDeletion = new UserDeletion();
            UserDeletion.deleteUser(loginId, userId, serviceId);
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while deleting the user from Inwebo", e);
        }
    }
}