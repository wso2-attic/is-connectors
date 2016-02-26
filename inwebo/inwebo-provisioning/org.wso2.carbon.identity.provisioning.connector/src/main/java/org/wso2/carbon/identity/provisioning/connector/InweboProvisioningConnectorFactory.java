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
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import java.util.ArrayList;
import java.util.List;

public class InweboProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    private static final Log log = LogFactory.getLog(InweboProvisioningConnectorFactory.class);
    private static final String CONNECTOR_TYPE = "inwebo";

    @Override
    protected AbstractOutboundProvisioningConnector buildConnector(
            Property[] provisioningProperties) throws IdentityProvisioningException {
        InweboProvisioningConnector connector = new InweboProvisioningConnector();
        connector.init(provisioningProperties);
        if (log.isDebugEnabled()) {
            log.debug("inwebo provisioning connector created successfully.");
        }
        return connector;
    }

    @Override
    public String getConnectorType() {
        return CONNECTOR_TYPE;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();
        Property userId = new Property();

        userId.setName(InweboConnectorConstants.INWEBO_USER_ID);
        userId.setDisplayName("UserId");
        userId.setRequired(true);
        userId.setDescription("Enter your Inwebo UserId(random number)");
        configProperties.add(userId);

        Property serviceId = new Property();
        serviceId.setName(InweboConnectorConstants.INWEBO_SERVICE_ID);
        serviceId.setDisplayName("Service Id");
        serviceId.setRequired(true);
        serviceId.setDescription("Enter your service Id");
        configProperties.add(serviceId);

        Property p12file = new Property();
        p12file.setName(InweboConnectorConstants.INWEBO_P12FILE);
        p12file.setDisplayName("P12FILE");
        p12file.setRequired(true);
        p12file.setDescription("Enter your p12_file path");
        configProperties.add(p12file);

        Property p12password = new Property();
        p12password.setName(InweboConnectorConstants.INWEBO_P12PASSWORD);
        p12password.setDisplayName("P12Password");
        p12password.setRequired(true);
        p12password.setDescription("Enter your p12_password");
        configProperties.add(p12password);

        Property test = new Property();
        test.setName(InweboConnectorConstants.INWEBO_TEST);
        test.setDisplayName("test");
        test.setRequired(true);
        test.setDescription("Enter your password");
        configProperties.add(test);

        Property firstName = new Property();
        firstName.setName(InweboConnectorConstants.INWEBO_FIRSTNAME);
        firstName.setDisplayName("FirstName");
        firstName.setRequired(true);
        firstName.setDescription("Enter your firstname");
        configProperties.add(firstName);

        Property name = new Property();
        name.setName(InweboConnectorConstants.INWEBO_NAME);
        name.setDisplayName("Name");
        name.setRequired(true);
        name.setDescription("Enter your name");
        configProperties.add(name);

        Property mail = new Property();
        mail.setName(InweboConnectorConstants.INWEBO_MAIL);
        mail.setDisplayName("Mail");
        mail.setRequired(true);
        mail.setDescription("Enter your mail address");
        configProperties.add(mail);

        Property phone = new Property();
        phone.setName(InweboConnectorConstants.INWEBO_PHONENUMBER);
        phone.setDisplayName("Phone Number");
        phone.setRequired(true);
        phone.setDescription("Enter your phone number");
        configProperties.add(phone);

        Property status = new Property();
        status.setName(InweboConnectorConstants.INWEBO_STATUS);
        status.setDisplayName("Status");
        status.setRequired(true);
        status.setDescription("Enter the status");
        configProperties.add(status);

        Property role = new Property();
        role.setName(InweboConnectorConstants.INWEBO_ROLE);
        role.setDisplayName("Role");
        role.setRequired(true);
        role.setDescription("Enter the role");
        configProperties.add(role);

        Property access = new Property();
        access.setName(InweboConnectorConstants.INWEBO_ACCESS);
        access.setDisplayName("Access");
        access.setRequired(true);
        access.setDescription("Enter the access level");
        configProperties.add(access);

        Property codeType = new Property();
        codeType.setName(InweboConnectorConstants.INWEBO_CODETYPE);
        codeType.setDisplayName("Code Type");
        codeType.setRequired(true);
        codeType.setDescription("Enter the code type");
        configProperties.add(codeType);
        return configProperties;
    }
}
