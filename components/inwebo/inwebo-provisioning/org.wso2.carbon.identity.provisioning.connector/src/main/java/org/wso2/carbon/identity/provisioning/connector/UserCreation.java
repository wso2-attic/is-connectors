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

public class UserCreation {
    private static final Log log = LogFactory.getLog(UserCreation.class);

    /**
     * Method for create SOAP connection
     */
    public static String invokeSOAP(String userId, String serviceId, String login, String firstName, String name,
                                    String mail, String phone, String status, String role, String access,
                                    String codeType, String language, String extraFields)
            throws IdentityProvisioningException {
        String provisionedId = null;
        SOAPConnectionFactory soapConnectionFactory = null;
        SOAPConnection soapConnection = null;
        try {
            soapConnectionFactory = SOAPConnectionFactory.newInstance();
            soapConnection = soapConnectionFactory.createConnection();
            String url = InweboConnectorConstants.INWEBO_URL;
            SOAPMessage soapResponse = soapConnection.call(createUser(userId, serviceId, login, firstName, name, mail, phone, status,
                    role, access, codeType, language, extraFields), url);
            provisionedId = soapResponse.getSOAPBody().getElementsByTagName("id").item(0).getTextContent().toString();
            if (StringUtils.isEmpty(provisionedId) || provisionedId.equals("0")) {
                String error = soapResponse.getSOAPBody().getElementsByTagName("loginCreateReturn").item(0)
                        .getTextContent().toString();
                throw new IdentityProvisioningException("Error occurred while creating the user in InWebo:" + error);
            }
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
        return provisionedId;
    }

    private static SOAPMessage createUser(String userId, String serviceId, String login, String firstName, String name,
                                          String mail, String phone, String status, String role, String access, String codetype,
                                          String language, String extrafields) throws SOAPException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = InweboConnectorConstants.INWEBO_URI;
        SOAPEnvelope envelope = soapPart.getEnvelope();
        String namespacePrefix = InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_NAMESPACE_PREFIX;
        envelope.addNamespaceDeclaration(namespacePrefix, serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem = soapBody.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ACTION_LOGIN_CREATE, namespacePrefix);
        SOAPElement soapBodyElem1 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_USER_ID, namespacePrefix);
        soapBodyElem1.addTextNode(userId);
        SOAPElement soapBodyElem2 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_SERVICE_ID, namespacePrefix);
        soapBodyElem2.addTextNode(serviceId);
        SOAPElement soapBodyElem3 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_LOGIN, namespacePrefix);
        soapBodyElem3.addTextNode(login);
        SOAPElement soapBodyElem4 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_FIRST_NAME, namespacePrefix);
        soapBodyElem4.addTextNode(firstName);
        SOAPElement soapBodyElem5 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_NAME, namespacePrefix);
        soapBodyElem5.addTextNode(name);
        SOAPElement soapBodyElem6 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_MAIL, namespacePrefix);
        soapBodyElem6.addTextNode(mail);
        SOAPElement soapBodyElem7 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_PHONE, namespacePrefix);
        soapBodyElem7.addTextNode(phone);
        SOAPElement soapBodyElem8 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_STATUS, namespacePrefix);
        soapBodyElem8.addTextNode(status);
        SOAPElement soapBodyElem9 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ROLE, namespacePrefix);
        soapBodyElem9.addTextNode(role);
        SOAPElement soapBodyElem10 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ACCESS, namespacePrefix);
        soapBodyElem10.addTextNode(access);
        SOAPElement soapBodyElem11 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_CONTENT_TYPE, namespacePrefix);
        soapBodyElem11.addTextNode(codetype);
        SOAPElement soapBodyElem12 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_LANG, namespacePrefix);
        soapBodyElem12.addTextNode(language);
        SOAPElement soapBodyElem13 = soapBodyElem.addChildElement(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_EXTRA_FIELDS, namespacePrefix);
        soapBodyElem13.addTextNode(extrafields);
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader(InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ACTION, serverURI
                + InweboConnectorConstants.InweboConnectorSOAPMessageConstants.SOAP_ACTION_HEADER);
        soapMessage.saveChanges();

        return soapMessage;
    }
}