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
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import javax.xml.soap.*;

public class UserUpdation {

    /**
     * Method for create SOAP connection
     */
    public static boolean invokeSOAP(String userId, String serviceId, String loginId, String login, String firstName,
                                     String name, String mail, String phone, String status, String role,
                                     String extraFields) throws IdentityProvisioningException {
        try {
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();
            String url = InweboConnectorConstants.INWEBO_URL;
            SOAPMessage soapResponse = soapConnection.call(createUserObject(userId, serviceId, loginId, login, firstName, name, mail,
                    phone, status, role, extraFields), url);
            String updationStatus = soapResponse.getSOAPBody().getElementsByTagName("loginUpdateReturn").item(0)
                    .getTextContent().toString();
            soapConnection.close();
            boolean processStatus = StringUtils.equals("OK", updationStatus);
            if (!processStatus) {
                String error = soapResponse.getSOAPBody().getElementsByTagName("loginUpdateReturn").item(0)
                        .getTextContent().toString();
                throw new IdentityProvisioningException("Error occurred while updating the user in InWebo:" + error);
            }
            return processStatus;
        } catch (SOAPException e) {
            throw new IdentityProvisioningException("Error occurred while sending SOAP Request to Server", e);
        } catch (IdentityProvisioningException e) {
            throw new IdentityProvisioningException("Error occurred while sending SOAP Request to Server", e);
        }
    }

    private static SOAPMessage createUserObject(String userId, String serviceId, String loginId, String login,
                                                String firstName, String name, String mail, String phone, String status,
                                                String role, String extraFields) throws SOAPException, IdentityProvisioningException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = InweboConnectorConstants.INWEBO_URI;
        SOAPEnvelope envelope = soapPart.getEnvelope();
        envelope.addNamespaceDeclaration("con", serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem = soapBody.addChildElement("loginUpdate", "con");
        SOAPElement soapBodyElem1 = soapBodyElem.addChildElement("userid", "con");
        soapBodyElem1.addTextNode(userId);
        SOAPElement soapBodyElem2 = soapBodyElem.addChildElement("serviceid", "con");
        soapBodyElem2.addTextNode(serviceId);
        SOAPElement soapBodyElem3 = soapBodyElem.addChildElement("loginid", "con");
        soapBodyElem3.addTextNode(loginId);
        SOAPElement soapBodyElem4 = soapBodyElem.addChildElement("login", "con");
        soapBodyElem4.addTextNode(login);
        SOAPElement soapBodyElem5 = soapBodyElem.addChildElement("firstname", "con");
        soapBodyElem5.addTextNode(firstName);
        SOAPElement soapBodyElem6 = soapBodyElem.addChildElement("name", "con");
        soapBodyElem6.addTextNode(name);
        SOAPElement soapBodyElem7 = soapBodyElem.addChildElement("mail", "con");
        soapBodyElem7.addTextNode(mail);
        SOAPElement soapBodyElem8 = soapBodyElem.addChildElement("phone", "con");
        soapBodyElem8.addTextNode(phone);
        SOAPElement soapBodyElem9 = soapBodyElem.addChildElement("status", "con");
        soapBodyElem9.addTextNode(status);
        SOAPElement soapBodyElem10 = soapBodyElem.addChildElement("role", "con");
        soapBodyElem10.addTextNode(role);
        SOAPElement soapBodyElem11 = soapBodyElem.addChildElement("extrafields", "con");
        soapBodyElem11.addTextNode(extraFields);
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader("SOAPAction", serverURI + "/services/ConsoleAdmin");
        soapMessage.saveChanges();
        return soapMessage;
    }
}