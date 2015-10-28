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

public class FoursquareAuthenticatorConstants {
    public static final String FOURSQUARE_OAUTH_ENDPOINT = "https://foursquare.com/oauth2/authenticate";
    public static final String FOURSQUARE_TOKEN_ENDPOINT = "https://foursquare.com/oauth2/access_token";
    public static final String FOURSQUARE_USER_INFO_ENDPOINT = "https://api.foursquare.com/v2/users/self?v=20151014";
    public static final String FOURSQUARE_CONNECTOR_FRIENDLY_NAME = "Foursquare ";
    public static final String FOURSQUARE_CONNECTOR_NAME = "Foursquare";
    public static final String FOURSQUARE_USER_ID = "id";
    public static final String FOURSQUARE_OAUTH2_ACCESS_TOKEN_PARAMETER = "oauth_token";
    public static final String HTTP_METHOD="GET";

    public static final String FOURSQUARE_LOGIN_TYPE = "foursquare";
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String OAUTH2_AUTHZ_URL = "OAuth2AuthUrl";
    public static final String OAUTH2_TOKEN_URL = "OAUTH2TokenUrl";

    public static class Claim  {
        public static final String ID = "id";
        public static final String FIRST_NAME = "firstName";
        public static final String LAST_NAME = "lastName";
        public static final String USER = "user";
        public static final String CONTACT= "contact";
        public static final String EMAIL = "email";
        public static final String RESPONSE="response";
    }
}