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

package org.wso2.carbon.identity.authenticator;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;

public class PushREST {

    private static final Log log = LogFactory.getLog(PushREST.class);
    private String serviceId;
    private String p12file;
    private String p12password;
    private String userId;

    public PushREST(String serviceId, String p12file, String p12password, String userId) {
        this.serviceId = serviceId;
        this.p12file = p12file;
        this.p12password = p12password;
        this.userId = userId;
    }

    /**
     * @param args
     */
    public void pushRESTCall() {
        String login;
        String SessionId;
        log.info("\nAsk Push notification ");

        log.info("Login? ");
        login = userId;

        PushAuthenticate pa = new PushAuthenticate(serviceId, p12file, p12password);
        JSONObject result = pa.pushAuthenticate(login);
        log.info("result: " + result.toJSONString());
        SessionId = (String) result.get("sessionId");
        log.info("SessionId: " + SessionId);
        CheckPushResult cr = new CheckPushResult(serviceId, p12file, p12password);
        if (SessionId == null) {
            log.info("no session id: " + result.get("err"));
            return;
        }
        while (true) {
            result = cr.checkPushResult(login, SessionId);
            if (!result.get("err").equals("NOK:WAITING")) break;
            try {
                log.info("request pending...  " + result);
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                log.error("Error while getting response" + e.getMessage(), e);
            }
        }
        log.info("result:" + result.get("err"));
        return;
    }

    public void run() {
        pushRESTCall();
    }
}


