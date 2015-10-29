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
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

public class PushRestCall {

    private static final Log log = LogFactory.getLog(PushRestCall.class);
    private String serviceId;
    private String p12file;
    private String p12password;
    private String userId;
    private int retryCount;

    public PushRestCall(String serviceId, String p12file, String p12password, String userId, int retryCount) {
        this.serviceId = serviceId;
        this.p12file = p12file;
        this.p12password = p12password;
        this.userId = userId;
        this.retryCount = retryCount;
    }

    public String invokePush() throws AuthenticationFailedException {
        String sessionId;
        log.info("\nAsk push notification ");

        PushAuthentication pushAuthentication = new PushAuthentication(serviceId, p12file, p12password);
        JSONObject result = pushAuthentication.pushAuthenticate(userId);
        if (log.isDebugEnabled()) {
            log.info("Result: " + result.toJSONString());
        }
        sessionId = (String) result.get("sessionId");
        if (log.isDebugEnabled()) {
            log.info("Session id: " + sessionId);
        }
        PushResult cr = new PushResult(serviceId, p12file, p12password);
        if (sessionId == null) {
            if (log.isDebugEnabled()) {
                log.info("No session id: " + result.get(InweboConstants.ERROR));
            }
            return result.toString();
        }
        int retry = 0;
        int maxRetryCount = 10;
        int waitTime = maxRetryCount > retryCount ? retryCount : maxRetryCount;
        while ((retry < waitTime)) {
            retry++;
            result = cr.checkPushResult(userId, sessionId);
            if (!result.get(InweboConstants.ERROR).equals(InweboConstants.CODEWAITTING)) break;
            try {
                log.info("Request pending...  " + result);
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                log.error("Error while getting response", e);
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
        }
        log.info("Result:" + result.get(InweboConstants.ERROR));
        return result.toString();
    }

    public String run() throws AuthenticationFailedException {
        return invokePush();
    }
}


