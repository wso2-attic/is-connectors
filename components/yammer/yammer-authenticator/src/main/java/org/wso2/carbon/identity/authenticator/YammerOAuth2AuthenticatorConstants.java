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

public class YammerOAuth2AuthenticatorConstants{

    public static final String YAMMER_OAUTH_ENDPOINT = "https://www.yammer.com/oauth2/authorize";
    public static final String YAMMER_TOKEN_ENDPOINT = "https://www.yammer.com/oauth2/access_token";
    public static final String YAMMER_USERINFO_ENDPOINT = "https://www.yammer.com/api/v1/users/current.json";

    public static final String YAMMER_CONNECTOR_FRIENDLY_NAME = "Yammer ";
    public static final String YAMMER_CONNECTOR_NAME = "YammerOauth2Authenticator";

    public static final String ACCESS_TOKEN = "token";
    public static final String TOKEN = "access_token";
    public static final String USER_ID = "user_id";

}