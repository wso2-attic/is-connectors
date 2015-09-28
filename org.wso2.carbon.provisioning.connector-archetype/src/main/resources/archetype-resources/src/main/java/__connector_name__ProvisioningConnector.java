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

package ${package};

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.*;

import java.util.Properties;

public class ${connector_name}ProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final Log log = LogFactory.getLog(${connector_name}ProvisioningConnector.class);
    private ${connector_name}ProvisioningConnectorConfig configHolder;

    @Override
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        Properties configs = new Properties();

        if (provisioningProperties != null && provisioningProperties.length > 0) {
            for (Property property : provisioningProperties) {
                //Add your code to add property to the configHolder
                configs.put(property.getName(), property.getValue());
                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property
                        .getName())) {
                    if ("1".equals(property.getValue())) {
                        jitProvisioningEnabled = true;
                    }
                }
            }
        }

        configHolder = new ${connector_name}ProvisioningConnectorConfig(configs);
    }

    @Override
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {
        String provisionedId = null;
        if (provisioningEntity != null) {
            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for ${connector_name} connector");
                return null;
            }

            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteUser(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    provisionedId = createUser(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                    update(provisioningEntity.getIdentifier().getIdentifier());
                } else {
                    log.warn("Unsupported provisioning operation.");
                }
            } else {
                log.warn("Unsupported provisioning operation.");
            }
        }

        // creates a provisioned identifier for the provisioned user.
        ProvisionedIdentifier identifier = new ProvisionedIdentifier();
        identifier.setIdentifier(provisionedId);
        return identifier;
    }

    /**
     * Create the user
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     */
    private String createUser(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {
        try {
            //Add your code here to create the user
        } catch (Exception e) {
            log.error("Error while creating the user");
            throw new IdentityProvisioningException(e);
        }
        return null;
    }

    /**
     * Delete the user
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {
       try {
            //Add your code here to delete the user
        } catch (Exception e) {
            log.error("Error while deleting the user");
            throw new IdentityProvisioningException(e);
        }
    }

    /**
     * Update the user
     * @param provsionedId
     * @return
     * @throws IdentityProvisioningException
     */
    private void update(String provsionedId)
            throws IdentityProvisioningException {
        try {
        //Add your code to update the user
        } catch (Exception e) {
            log.error("Error while updating the user");
            throw new IdentityProvisioningException(e);
        }
    }

    /**
     * List the users
     * @return
     * @throws IdentityProvisioningException
     */
    public String listUsers(String query) throws IdentityProvisioningException {
        try {
        //Add your code to list the user
        } catch (Exception e) {
            log.error("Error while listing the user");
            throw new IdentityProvisioningException(e);
        }
        return null;
    }

}
