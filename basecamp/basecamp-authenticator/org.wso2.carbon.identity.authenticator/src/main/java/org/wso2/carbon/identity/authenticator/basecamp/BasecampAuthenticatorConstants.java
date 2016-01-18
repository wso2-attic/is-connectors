/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.authenticator.basecamp;

public class BasecampAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "BasecampAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Basecamp";

    //Basecamp authorize endpoint URL
    public static final String BASECAMP_OAUTH_ENDPOINT = "https://launchpad.37signals.com/authorization/new";
    //Basecamp token  endpoint URL
    public static final String BASECAMP_TOKEN_ENDPOINT = "https://launchpad.37signals.com/authorization/token";
    //Basecamp user info endpoint URL
    public static final String BASECAMP_USERINFO_ENDPOINT = "https://launchpad.37signals.com/authorization.json";
    public static final String BASECAMP_EMAIL_ADDRESS = "email_address";
    public static final String OAUTH2_TYPE_WEB_SERVER = "web_server";
}