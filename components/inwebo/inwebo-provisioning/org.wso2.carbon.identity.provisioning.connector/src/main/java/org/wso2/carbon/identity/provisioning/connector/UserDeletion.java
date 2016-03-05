/*
 * Copyright (c) 2015-2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.provisioning.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPPart;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPException;

public class UserDeletion {
    private static final Log log = LogFactory.getLog(UserDeletion.class);

    public boolean deleteUser(String loginId, String userId, String serviceId) throws IdentityProvisioningException {
        SOAPConnectionFactory soapConnectionFactory = null;
        SOAPConnection soapConnection = null;
        try {
            soapConnectionFactory = SOAPConnectionFactory.newInstance();
            soapConnection = soapConnectionFactory.createConnection();
            String url = InweboConnectorConstants.INWEBO_URL;
            SOAPMessage soapResponse = soapConnection.call(deleteUsers(loginId, userId, serviceId), url);
            String deletionStatus = soapResponse.getSOAPBody().getElementsByTagName("loginDeleteReturn").item(0)
                    .getTextContent().toString();
            boolean processStatus = StringUtils.equals("OK", deletionStatus);
            if (!processStatus) {
                String error = soapResponse.getSOAPBody().getElementsByTagName("loginDeleteReturn").item(0)
                        .getTextContent().toString();
                throw new IdentityProvisioningException("Error occurred while deleting the user from InWebo:" + error);
            }
            return processStatus;
        } catch (SOAPException e) {
            throw new IdentityProvisioningException("Error occurred while sending SOAP Request to Server", e);
        } finally {
            try {
                if (soapConnection != null) {
                    soapConnection.close();
                }
            } catch (SOAPException e) {
                log.error("Error while closing the SOAP connection", e);
            }
        }
    }

    private static SOAPMessage deleteUsers(String loginId, String userId, String serviceId) throws SOAPException {

        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = InweboConnectorConstants.INWEBO_URI;
        SOAPEnvelope envelope = soapPart.getEnvelope();
        String namespacePrefix = InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_NAMESPACE_PREFIX;
        envelope.addNamespaceDeclaration(namespacePrefix, serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem =
                soapBody.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ACTION_LOGIN_DELETE, namespacePrefix);
        SOAPElement soapBodyElem1 =
                soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_USER_ID, namespacePrefix);
        soapBodyElem1.addTextNode(userId);
        SOAPElement soapBodyElem2 =
                soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_SERVICE_ID, namespacePrefix);
        soapBodyElem2.addTextNode(serviceId);
        SOAPElement soapBodyElem3 =
                soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_LOGIN_ID, namespacePrefix);
        soapBodyElem3.addTextNode(loginId);
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ACTION, serverURI
                + InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ACTION_HEADER);
        soapMessage.saveChanges();
        return soapMessage;
    }
}