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


import org.json.simple.JSONObject;

public class PushREST {

	private String serviceId;
	private String p12file;
	private String p12password;
    private String userId;
	
	public PushREST(String serviceId, String p12file, String p12password, String userId)
	{		
		this.serviceId = serviceId;
		this.p12file = p12file;
		this.p12password = p12password;
        this.userId=userId;
    }
	/**
	 * @param args
	 */
	public void pushRESTCall()
	{
		String login;
		String SessionId;
		System.out.println("\nAsk Push notification ");
		
		System.out.println("Login? ");
		login = userId;
		
		PushAuthenticate pa = new PushAuthenticate(serviceId, p12file, p12password);
		JSONObject result = pa.pushAuthenticate(login);
		System.out.println("result: " + result.toJSONString());
		SessionId = (String) result.get("sessionId");
		System.out.println("SessionId: " + SessionId);
		CheckPushResult cr = new CheckPushResult(serviceId, p12file, p12password);
		if (SessionId == null) {
			System.out.println("no session id: " + result.get("err"));
			return;
		}
		while (true) {
			result = cr.checkPushResult(login, SessionId);
			if (!result.get("err").equals("NOK:WAITING")) break;
			try {
				System.out.println("request pending...  " + result);
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		System.out.println("result:" + result.get("err"));
		return;
	}
	
	public void run()
	{
		pushRESTCall();
	}

}


