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

package org.wso2.carbon.identity.provisioning.connector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
        String provisionedId = null;
        if (provisioningEntity != null) {
            String login = provisioningEntity.getEntityName().toString();
            String userId = configHolder.getValue("UserId");
            String serviceId = configHolder.getValue("ServiceId");
            String p12file = configHolder.getValue("P12file");
            String p12password = configHolder.getValue("test");
            String firstName = configHolder.getValue("FirstName");
            String name = configHolder.getValue("Name");
            String mail = configHolder.getValue("Mail");
            String phone = configHolder.getValue("PhoneNumber");
            String status = configHolder.getValue("Status");
            String role = configHolder.getValue("Role");
            String access = configHolder.getValue("Access");
            String codeType = configHolder.getValue("CodeType");

            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for inwebo connector");
                return null;
            }
            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    provisionedId = createAUser(provisioningEntity, login, userId, serviceId, p12file, p12password, firstName,
                            name, mail, phone, status, role, access, codeType);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteUser(provisioningEntity, p12file, p12password, serviceId);
                } else {
                    throw new IdentityProvisioningException("Unsupported provisioning opertaion.");
                }
            } else {
                throw new IdentityProvisioningException("Unsupported provisioning opertaion.");
            }
        }
        // creates a provisioned identifier for the provisioned user.
        ProvisionedIdentifier identifier = new ProvisionedIdentifier();
        identifier.setIdentifier(provisionedId);
        return identifier;
    }

    private String createAUser(ProvisioningEntity provisioningEntity, String login, String userId, String serviceId, String p12file, String p12password, String firstName, String name,
                               String mail, String phone, String status, String role, String access, String codeType)
            throws IdentityProvisioningException {
        boolean isDebugEnabled = log.isDebugEnabled();
        String provisionedId = null;
        try {
            Util.setHttpsClientCert(p12file, p12password);
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while adding certificate", e);

        }
        try {
            UserCreation userCreation = new UserCreation(login, userId, serviceId, firstName, name, mail,
                    phone, status, role, access, codeType, p12file, p12password);
            provisionedId = userCreation.invokeSOAP();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while creating the user", e);
        }
        return provisionedId;
    }

    /**
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity provisioningEntity, String p12file, String p12password, String serviceId)
            throws IdentityProvisioningException {
        try {
            Util.setHttpsClientCert(p12file, p12password);
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while adding certificate", e);
        }
        try {
            String userId = provisioningEntity.getIdentifier().getIdentifier();
            UserDeletion UserDeletion = new UserDeletion(userId, serviceId);
            UserDeletion.deleteUser();
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error while creating the user", e);
        }
    }
}



