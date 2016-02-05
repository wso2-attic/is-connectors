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

package org.wso2.carbon.identity.authenticator;

public class InweboConstants {
    public static final String AUTHENTICATOR_NAME = "Inwebo";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Inwebo";
    public static final String INWEBO_P12FILE = "p12file";
    public static final String INWEBO_P12PASSWORD = "p12password";
    public static final String SERVICE_ID = "ServiceId";
    public static final String RESULT = "err";
    public static final String ENCODING = "UTF-8";
    public static final String PUSHRESPONSE = "\"err\":\"OK\"";
    public static final String RETRY_COUNT = "retrycount";
    public static final String CODEWAITTING = "NOK:WAITING";
    public static final String INWEBOURL = "https://api.myinwebo.com/FS?";
    public static final String SUNFORMAT = "SunX509";
    public static final String PKCSFORMAT = "PKCS12";
    public static final String TLSFORMAT = "TLS";
    public static final String RETRY_INTERVAL = "RetryInterval";
    public static final String RETRYINTERVAL_DEFAULT = "1000";
    public static final String WAITTIME_DEFAULT = "10";
    public static final String INWEBO_USERID = "http://wso2.org/claims/authentication/inwebo/userId";
    public static final String INWEBO_LOGINPAGE="authenticationendpoint/login.do";
    public static final String INWEBO_PAGE="inweboauthenticationendpoint/inwebo.jsp";
    public static final String RETRY_PARAM="&authFailure=true&authFailureMsg=authentication.fail.message";
}