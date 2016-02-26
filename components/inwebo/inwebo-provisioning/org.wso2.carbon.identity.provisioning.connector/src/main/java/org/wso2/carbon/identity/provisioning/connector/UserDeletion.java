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

public class UserDeletion {
    public static String loginId;
    public static String serviceId;

    public UserDeletion(String userId, String serviceId) {
        this.loginId = userId;
        this.serviceId = serviceId;
    }

    public void deleteUser() throws IdentityProvisioningException {
        try {
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();
            String url = InweboConnectorConstants.INWEBO_URL;
            soapConnection.call(deleteUsers(), url);
            soapConnection.close();
        } catch (SOAPException e) {
            throw new IdentityProvisioningException("Error occurred while sending SOAP Request to Server",e);
        }
    }

    private static SOAPMessage deleteUsers() throws SOAPException, IdentityProvisioningException {

            MessageFactory messageFactory = MessageFactory.newInstance();
            SOAPMessage soapMessage = messageFactory.createMessage();
        try {
            SOAPPart soapPart = soapMessage.getSOAPPart();
            String serverURI = InweboConnectorConstants.INWEBO_URI;
            SOAPEnvelope envelope = soapPart.getEnvelope();
            envelope.addNamespaceDeclaration("con", serverURI);
            SOAPBody soapBody = envelope.getBody();
            SOAPElement soapBodyElem = soapBody.addChildElement("loginDelete", "con");
            SOAPElement soapBodyElem1 = soapBodyElem.addChildElement("userid", "con");
            soapBodyElem1.addTextNode("123456");
            SOAPElement soapBodyElem2 = soapBodyElem.addChildElement("serviceid", "con");
            soapBodyElem2.addTextNode(UserDeletion.serviceId);
            SOAPElement soapBodyElem3 = soapBodyElem.addChildElement("loginid", "con");
            soapBodyElem3.addTextNode(UserDeletion.loginId);
            MimeHeaders headers = soapMessage.getMimeHeaders();
            headers.addHeader("SOAPAction", serverURI + "/services/ConsoleAdmin");
            soapMessage.saveChanges();
        }catch (SOAPException e){
            throw new IdentityProvisioningException("Error while delete the user",e);
        }
        return soapMessage;
    }
}
