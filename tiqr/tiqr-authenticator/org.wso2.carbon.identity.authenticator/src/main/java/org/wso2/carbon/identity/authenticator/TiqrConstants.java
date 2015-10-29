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

public class TiqrConstants {
    public static final String AUTHENTICATOR_NAME = "Tiqr";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Tiqr";
    public static final String TIQR_CLIENT_IP = "clientIP";
    public static final String ENROLL_USERID = "userId";
    public static final String ENROLL_DISPLAYNAME = "displayName";
    public static final String ENROLL_QRCODE = "qrCode";
    public static final String ENROLL_SESSIONID = "sessionId";
    public static final String ENROLLMENT_SUCCESS_STATUS = "5";
    public static final String TIQR_WAIT_TIME = "waitTime";
    public static final String HTTP_POST = "POST";
    public static final String HTTP_CONTENT_TYPE = "Content-Type";
    public static final String HTTP_CONTENT_TYPE_XWFUE = "application/x-www-form-urlencoded";
    public static final String PROTOCOL = "http://";
    public static final String CHARSET = "UTF-8";
    public static final String TIQR_CLIENT_PORT = "port";

    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String LOCAL = "LOCAL";
    public static final String FAILURE_REASON = "showAuthFailureReason";

    public static final String UNABLE_TO_CONNECT = "Unable to connect the tiqr client";
}