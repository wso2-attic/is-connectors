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

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class PushREST {

    private static final Log log = LogFactory.getLog(PushREST.class);
    private String serviceId;
    private String p12file;
    private String p12password;
    private String userId;
    private int retryCount;
    private int retryInterval;

    public PushREST(String serviceId, String p12file, String p12password, String userId, int retryCount, int retryInterval) {
        this.serviceId = serviceId;
        this.p12file = p12file;
        this.p12password = p12password;
        this.userId = userId;
        this.retryCount = retryCount;
        this.retryInterval = retryInterval;
    }

    public String pushRESTCall() {
        String SessionId;
        log.info("\nAsk Push notification ");

        PushAuthenticate pushAuthenticate = new PushAuthenticate(serviceId, p12file, p12password);
        JSONObject result = pushAuthenticate.pushAuthenticate(userId);
        if (log.isDebugEnabled()) {
            log.info("result: " + result.toJSONString());
        }
        SessionId = (String) result.get("sessionId");
        if (log.isDebugEnabled()) {
            log.info("SessionId: " + SessionId);
        }
        CheckPushResult cr = new CheckPushResult(serviceId, p12file, p12password);
        if (SessionId == null) {
            if (log.isDebugEnabled()) {
                log.info("no session id: " + result.get(InweboConstants.ERROR));
            }
            return result.toString();
        }
        int retry = 0;
        while ((retry < retryCount)) {
            retry++;
            result = cr.checkPushResult(userId, SessionId);
            if (!result.get(InweboConstants.ERROR).equals(InweboConstants.CODEWAITTING)) break;
            try {
                log.info("request pending...  " + result);
                Thread.sleep(retryInterval);
            } catch (InterruptedException e) {
                log.error("Error while getting response" + e.getMessage(), e);
            }
        }
        log.info("result:" + result.get(InweboConstants.ERROR));
        return result.toString();
    }

    public String run() {
        return pushRESTCall();
    }

    public static void showServlet(HttpServletResponse response, String relyingParty, String type, String finalReferer) {
        response.setContentType("text/html");
        PrintWriter out = null;
        try {
            out = response.getWriter();
            out.println("<title>Inwebo</title>" +
                    "<body bgcolor=FFFFFF>");
            out.println("<h2>Waiting for client authentication...</h2>");
            out.print("<A HREF=" + finalReferer + "/" + relyingParty +"/"+ type + ">Click to view details</A>");
            out.println("</body");
            out.close();
        } catch (IOException e) {
            log.error("Failure");
        }
    }
}


