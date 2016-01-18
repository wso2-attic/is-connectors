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

package org.wso2.carbon.identity.authenticator.wordpress;

public class WordpressAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "WordpressAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Wordpress";

    //Wordpress authorize endpoint URL
    public static final String WORDPRESS_OAUTH_ENDPOINT = "https://public-api.wordpress.com/oauth2/authorize";
    //Wordpress token  endpoint URL
    public static final String WORDPRESS_TOKEN_ENDPOINT = "https://public-api.wordpress.com/oauth2/token";
    //Wordpress user info endpoint URL
    public static final String WORDPRESS_USERINFO_ENDPOINT = "https://public-api.wordpress.com/rest/v1/me";

    public static final String CLIENT_ID="Client Id";
    public static final String CLIENT_SECRET="Client Secret";
    public static final String CALLBACK_URL="Callback URL";
    public static final String USER_ID="blog_id";
}