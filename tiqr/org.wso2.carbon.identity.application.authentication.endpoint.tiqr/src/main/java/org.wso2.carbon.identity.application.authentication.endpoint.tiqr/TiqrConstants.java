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

package org.wso2.carbon.identity.application.authentication.endpoint.tiqr;

public class TiqrConstants {
    public static final String ENROLL_USERID = "userId";
    public static final String ENROLL_DISPLAYNAME = "displayName";
    public static final String AUTH_USERNAME = "username";
    public static final String AUTH_PASSWORD = "password";
    public static final String TIQR_ACTION = "tiqrAction";
    public static final String TIQR_ACTION_AUTHENTICATION = "authentication";
    public static final String HTTP_POST = "POST";
    public static final String HTTP_GET = "GET";
    public static final String HTTP_CONTENT_TYPE = "Content-Type";
    public static final String HTTP_CONTENT_TYPE_XWFUE = "application/x-www-form-urlencoded";
    public static final String CHARSET = "UTF-8";
    public static final String TIQR_CLIENT_IP = "clientIP";
    public static final String TIQR_CLIENT_PORT = "port";
    public static final String INVALID_INPUT = "Invalid Input";
    public static final String UNABLE_TO_CONNECT = "Unable to connect the tiqr client";
    public static final String REQUIRED_PARAMS_NULL = "Required parameters are null";
    public static final String NULL_AUTHSTATE = "Unable to get authentication state";
    public static final String USERID_EXISTS = "Account already exists";
    public static final String FAILED = "Failed: ";
    public static final String PROTOCOL = "http://";
    public static final String AUTH_FAILURE_MSG = "authFailureMsg";
    public static final String IDP_AUTHENTICATOR_MAP = "idpAuthenticatorMap";
    public static final String AUTH_FAILURE = "authFailure";
    public static final String TIQR_CLIENT_NEW_USER_URL = "/module.php/authTiqr/newuser.php?AuthState=";
    public static final String TIQR_CLIENT_AUTHENTICATE_URL = "/module.php/authTiqr/login.php?AuthState=";
}