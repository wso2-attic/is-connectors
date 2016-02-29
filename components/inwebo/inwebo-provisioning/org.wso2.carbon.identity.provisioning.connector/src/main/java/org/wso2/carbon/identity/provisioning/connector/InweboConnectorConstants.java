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

public class InweboConnectorConstants {
    public static final String INWEBO_P12FILE = "P12file";
    public static final String INWEBO_P12PASSWORD = "P12KeystorePassword";
    public static final String INWEBO_USER_ID = "UserId";
    public static final String INWEBO_FIRSTNAME = "FirstName";
    public static final String INWEBO_NAME = "Name";
    public static final String INWEBO_MAIL = "Mail";
    public static final String INWEBO_PHONENUMBER = "PhoneNumber";
    public static final String INWEBO_STATUS = "Status";
    public static final String INWEBO_ROLE = "Role";
    public static final String INWEBO_ACCESS = "Access";
    public static final String INWEBO_SERVICE_ID = "ServiceId";
    public static final String INWEBO_CODETYPE = "CodeType";
    public static final String INWEBO_EXTRAFIELDS = "ExtraFields";
    public static final String INWEBO_LANG = "Language";

    public static final String INWEBO_URL = "https://api.myinwebo.com/services/ConsoleAdmin";
    public static final String INWEBO_URI = "http://console.inwebo.com";
    public static final String AXIS2 = "axis2.xml";
    public static final String AXIS2_FILE = "repository/conf/axis2/axis2_inwebo.xml";
    public static final String INWEBO_LANG_ENGLISH = "En";
    class InweboConnectorClaims {
        public static final String IDP_CLAIM_URI_FIRSTNAME = "firstName";
        public static final String IDP_CLAIM_URI_LARSTNAME = "lastName";
        public static final String IDP_CLAIM_URI_EMAIL = "email";
        public static final String IDP_CLAIM_URI_PHONE = "phone";
        public static final String USERNAME_CLAIM = "org:wso2:carbon:identity:provisioning:claim:username";
        public static final String FIRST_NAME_CLAIM = "http://wso2.org/claims/givenname";
        public static final String LAST_NAME_CLAIM = "http://wso2.org/claims/lastname";
        public static final String MAIL_CLAIM = "http://wso2.org/claims/emailaddress";
        public static final String PHONE_CLAIM = "http://wso2.org/claims/telephone";
    }
    class InweboConnectorSOAPMessageConstants {
        public static final String SOAP_ACTION = "SOAPAction";
        public static final String SOAP_ACTION_HEADER = "/services/ConsoleAdmin";
        public static final String SOAP_NAMESPACE_PREFIX = "con";
        public static final String SOAP_ACTION_LOGIN_CREATE = "loginCreate";
        public static final String SOAP_ACTION_LOGIN_DELETE = "loginDelete";
        public static final String SOAP_ACTION_LOGIN_UPDATE = "loginUpdate";
        public static final String SOAP_USER_ID = "userid";
        public static final String SOAP_SERVICE_ID = "serviceid";
        public static final String SOAP_LOGIN = "login";
        public static final String SOAP_FIRST_NAME = "firstname";
        public static final String SOAP_NAME = "name";
        public static final String SOAP_MAIL = "mail";
        public static final String SOAP_PHONE = "phone";
        public static final String SOAP_STATUS = "status";
        public static final String SOAP_ROLE = "role";
        public static final String SOAP_ACCESS = "access";
        public static final String SOAP_CONTENT_TYPE = "codetype";
        public static final String SOAP_LANG = "lang";
        public static final String SOAP_EXTRA_FIELDS = "extrafields";
        public static final String SOAP_LOGIN_ID = "loginid";
    }
}