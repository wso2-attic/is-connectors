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

package org.wso2.carbon.identity.authenticator.mailChimp;

public class MailChimpAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "MailChimpAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "MailChimp";

    //MailChimp authorize endpoint URL
    public static final String MailChimp_OAUTH_ENDPOINT = "https://login.mailchimp.com/oauth2/authorize";
    //MailChimp token  endpoint URL
    public static final String MailChimp_TOKEN_ENDPOINT = "https://login.mailchimp.com/oauth2/token";
    //MailChimp user info endpoint URL
    public static final String MailChimp_USERINFO_ENDPOINT = "https://us12.api.mailchimp.com/2.0/users/profile";

    public static final String MailChimp_EMAIL = "email";
    public static final String CLIENT_ID = "Client Id";
    public static final String CLIENT_SECRET = "Client Secret";
    public static final String CALLBACK_URL = "Callback URL";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String USER_CLAIMS = "UserClaims";
    public static final String USER_ID_TOKEN = "UserIdToken";
    public static final String RESPONSE = "response: ";
    public static final String REQUEST_METHOD = "POST";
}