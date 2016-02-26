/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import java.io.IOException;

public class UserCreation {
    public static String provisionedId = null;
    private static String userId;
    private static String serviceId;
    private static String login;
    private static String firstName;
    private static String name;
    private static String mail;
    private static String phone;
    private static String status;
    private static String role;
    private static String access;
    private static String codetype;
    private static String p12file;
    private static String p12password;

    public UserCreation(String login, String userId, String serviceId, String firstName, String name,
                        String mail, String phone, String status, String role, String access, String codetype,
                        String p12file, String p12password) {
        this.userId = userId;
        this.serviceId = serviceId;
        this.login = login;
        this.firstName = firstName;
        this.name = name;
        this.mail = mail;
        this.phone = phone;
        this.status = status;
        this.role = role;
        this.access = access;
        this.codetype = codetype;
        this.p12file = p12file;
        this.p12password = p12password;

    }

    /**
     * Method for create SOAP connection
     */
    public static String invokeSOAP() throws IdentityProvisioningException {
        try {
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();
            String url = InweboConnectorConstants.INWEBO_URL;
            SOAPMessage soapResponse = soapConnection.call(createUser(), url);
            provisionedId = soapResponse.getSOAPBody().getElementsByTagName("id").item(0).getTextContent().toString();
            soapConnection.close();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error occurred while sending SOAP Request to Server", e);
        }
        return provisionedId;
    }

    private static SOAPMessage createUser() throws SOAPException, IdentityProvisioningException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = InweboConnectorConstants.INWEBO_URI;
        SOAPEnvelope envelope = soapPart.getEnvelope();
        envelope.addNamespaceDeclaration("con", serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem = soapBody.addChildElement("loginCreate", "con");
        SOAPElement soapBodyElem1 = soapBodyElem.addChildElement("userid", "con");
        soapBodyElem1.addTextNode(UserCreation.userId);
        SOAPElement soapBodyElem2 = soapBodyElem.addChildElement("serviceid", "con");
        soapBodyElem2.addTextNode(UserCreation.serviceId);
        SOAPElement soapBodyElem3 = soapBodyElem.addChildElement("login", "con");
        soapBodyElem3.addTextNode(UserCreation.login);
        SOAPElement soapBodyElem4 = soapBodyElem.addChildElement("firstname", "con");
        soapBodyElem4.addTextNode(UserCreation.firstName);
        SOAPElement soapBodyElem5 = soapBodyElem.addChildElement("name", "con");
        soapBodyElem5.addTextNode(UserCreation.name);
        SOAPElement soapBodyElem6 = soapBodyElem.addChildElement("mail", "con");
        soapBodyElem6.addTextNode(UserCreation.mail);
        SOAPElement soapBodyElem7 = soapBodyElem.addChildElement("phone", "con");
        soapBodyElem7.addTextNode(UserCreation.phone);
        SOAPElement soapBodyElem8 = soapBodyElem.addChildElement("status", "con");
        soapBodyElem8.addTextNode(UserCreation.status);
        SOAPElement soapBodyElem9 = soapBodyElem.addChildElement("role", "con");
        soapBodyElem9.addTextNode(UserCreation.role);
        SOAPElement soapBodyElem10 = soapBodyElem.addChildElement("access", "con");
        soapBodyElem10.addTextNode(UserCreation.access);
        SOAPElement soapBodyElem11 = soapBodyElem.addChildElement("codetype", "con");
        soapBodyElem11.addTextNode(UserCreation.codetype);
        SOAPElement soapBodyElem12 = soapBodyElem.addChildElement("lang", "con");
        soapBodyElem12.addTextNode("En");
        SOAPElement soapBodyElem13 = soapBodyElem.addChildElement("extrafields", "con");
        soapBodyElem13.addTextNode("");
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader("SOAPAction", serverURI + "/services/ConsoleAdmin");
        headers.addHeader("Content-Length", String.valueOf(InweboConnectorConstants.CONTENT_LENGTH));
        soapMessage.saveChanges();
        //         Print the request message
        System.out.print("Request SOAP Message = ");
        try {
            soapMessage.writeTo(System.out);
        } catch (IOException e) {
            throw new IdentityProvisioningException("Error while printing",e);
        }
        System.out.println();
        return soapMessage;
    }
}