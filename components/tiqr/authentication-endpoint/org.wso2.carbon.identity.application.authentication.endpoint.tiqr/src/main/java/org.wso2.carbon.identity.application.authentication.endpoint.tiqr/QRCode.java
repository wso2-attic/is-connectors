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

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.OutputStreamWriter;
import java.io.InputStreamReader;
import java.lang.String;
import java.net.URL;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

@WebServlet("/QRCode")
public class QRCode extends HttpServlet {
    private static Log log = LogFactory.getLog(QRCode.class);
    private static final long serialVersionUID = 1L;

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter(TiqrConstants.AUTH_USERNAME).trim();
        String password = request.getParameter(TiqrConstants.AUTH_PASSWORD).trim();
        String userId = request.getParameter(TiqrConstants.ENROLL_USERID).trim();
        String displayName = request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME).trim();
        String tiqrAction = request.getParameter(TiqrConstants.TIQR_ACTION).trim();
        String res = "";
        if (!StringUtils.isEmpty(username) && !StringUtils.isEmpty(password) && !StringUtils.isEmpty(userId)
                && !StringUtils.isEmpty(displayName)) {
            String enrolUserResponse = enrolUser(request);
            if (enrolUserResponse.startsWith(TiqrConstants.FAILED)) {
                log.error("Unable to show the QR code for enrollment: "
                        + enrolUserResponse.replace("Failed:", "").trim());
                res = enrolUserResponse;
            } else {
                String authState = getAuthState(request, enrolUserResponse);
                authState = authState.substring(0, authState.indexOf("&sessionId=")).trim();
                if (!StringUtils.isEmpty(authState)) {
                    res = "<input type='hidden' name='authState' id='authState' value='" + authState + "'/>";
                }
                String qrCode = getQrCode(enrolUserResponse);
                if (!StringUtils.isEmpty(qrCode)) {
                    res = res + qrCode.replace("/>", " style=\"padding-left: 50px; padding-right: 50px;\" " +
                            "data-toggle=\"tooltip\" title=\"Scan this QR code via tiqr mobile application to " +
                            "enroll the user\"/>");
                }
                String sessionId = getSessionID(enrolUserResponse);
                if (!StringUtils.isEmpty(sessionId)) {
                    res = res + "<input type='hidden' name='sessionId' id='sessionId' value='" + sessionId + "'/>";
                }
            }
        } else if (tiqrAction.equals(TiqrConstants.TIQR_ACTION_AUTHENTICATION)) {
            String authState = getAuthState(request, "");
            if (!StringUtils.isEmpty(authState)) {
                String tiqrEP = getTiqrEndpoint(request);
                String urlToAuthenticate = tiqrEP + TiqrConstants.TIQR_CLIENT_AUTHENTICATE_URL + authState;
                String authenticationResponse = sendRESTCall(urlToAuthenticate, "", "", TiqrConstants.HTTP_GET);
                authState = authState.substring(0, authState.indexOf("&sessionId=")).trim();
                if (authenticationResponse.startsWith(TiqrConstants.FAILED)) {
                    log.error("Unable to show the QR code for authentication: "
                            + authenticationResponse.replace("Failed:", "").trim());
                    res = authenticationResponse;
                } else {
                    if (!StringUtils.isEmpty(authState)) {
                        res = "<input type='hidden' name='authState' id='authState' value='" + authState + "'/>";
                    }
                    String qrCode = getQrCode(authenticationResponse);
                    if (!StringUtils.isEmpty(qrCode)) {
                        res = res + qrCode.replace("/>", " style=\"padding-left: 50px; padding-right: 50px;\" " +
                                "data-toggle=\"tooltip\" title=\"Scan this QR code via tiqr mobile application to " +
                                "authenticate the user\"/>");
                    }
                    String sessionId = getSessionID(authenticationResponse);
                    if (!StringUtils.isEmpty(sessionId)) {
                        res = res + "<input type='hidden' name='sessionId' id='sessionId' value='" + sessionId + "'/>";
                    }
                }
            } else {
                res = TiqrConstants.FAILED + TiqrConstants.UNABLE_TO_CONNECT;
            }
        } else {
            res = TiqrConstants.FAILED + TiqrConstants.INVALID_INPUT;
        }
        response.setContentType("text/plain");
        response.getWriter().write(res);
    }

    /**
     * Get auth state
     */
    private String getAuthState(HttpServletRequest request, String body) {
        String tiqrEP = getTiqrEndpoint(request);
        String getAuthStateResponse = TiqrConstants.FAILED;
        if (!StringUtils.isEmpty(body)) {
            getAuthStateResponse = body;
        } else {
            String urlToGetAuthState = tiqrEP + TiqrConstants.TIQR_CLIENT_NEW_USER_URL.replace("?AuthState=", "");
            getAuthStateResponse = sendRESTCall(urlToGetAuthState, "", "", TiqrConstants.HTTP_GET);
        }
        if (getAuthStateResponse.startsWith(TiqrConstants.FAILED)) {
            return null;
        } else {
            return getAuthStateResponse.substring(getAuthStateResponse.indexOf("name=\"AuthState\" value=\"")
                    , getAuthStateResponse.indexOf("\" id=\"AuthState\"/>")).replace("name=\"AuthState\" value=\"", "")
                    .trim() + "&sessionId=" + getSessionID(getAuthStateResponse);
        }
    }

    /**
     * Connect with the tiqr client
     */
    private String enrolUser(HttpServletRequest request) {
        String tiqrEP = getTiqrEndpoint(request);
        String authState = getAuthState(request, "");
        if (!StringUtils.isEmpty(authState)) {
            String urlToEntrol = tiqrEP + TiqrConstants.TIQR_CLIENT_NEW_USER_URL + authState;
            String userId = request.getParameter(TiqrConstants.ENROLL_USERID);
            String diaplayName = request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME);
            if (!StringUtils.isEmpty(userId) && !StringUtils.isEmpty(diaplayName)) {
                String formParameters = "userId=" + userId + "&displayName=" + diaplayName + "&create=1";
                String result = sendRESTCall(urlToEntrol, "", formParameters, TiqrConstants.HTTP_POST);
                if (result.contains("Invalid user ID")) {
                    return TiqrConstants.FAILED + TiqrConstants.INVALID_INPUT;
                } else if (result.contains("Account already exists")) {
                    return TiqrConstants.FAILED + TiqrConstants.USERID_EXISTS;
                }
                return result;
            } else {
                return TiqrConstants.FAILED + TiqrConstants.REQUIRED_PARAMS_NULL;
            }
        } else {
            return TiqrConstants.FAILED + TiqrConstants.NULL_AUTHSTATE;
        }
    }

    /**
     * Send REST call
     */
    private String sendRESTCall(String url, String urlParameters, String formParameters, String httpMethod) {
        String line;
        StringBuilder responseString = new StringBuilder();
        HttpURLConnection connection = null;
        try {
            URL tiqrEP = new URL(url + urlParameters);
            connection = (HttpURLConnection) tiqrEP.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(httpMethod);
            connection.setRequestProperty(TiqrConstants.HTTP_CONTENT_TYPE, TiqrConstants.HTTP_CONTENT_TYPE_XWFUE);
            if (httpMethod.toUpperCase().equals(TiqrConstants.HTTP_POST)) {
                OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream(), TiqrConstants.CHARSET);
                writer.write(formParameters);
                writer.close();
            }
            if (connection.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                while ((line = br.readLine()) != null) {
                    responseString.append(line);
                }
                br.close();
            } else {
                return TiqrConstants.FAILED + TiqrConstants.UNABLE_TO_CONNECT;
            }
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(TiqrConstants.FAILED + e.getMessage());
            }
            return TiqrConstants.FAILED + e.getMessage();
        } finally {
            connection.disconnect();
        }
        return responseString.toString();
    }

    /**
     * Get the tiqr QR code
     */
    protected String getQrCode(String result) {
        try {
            if (!result.contains("<img alt=\"QR\"")) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to find QR code");
                }
                return null;
            }
            return result.substring(result.indexOf("<img"), result.indexOf("id=\"QR\"/>")) + "id=\"QR\"/>";
        } catch (IndexOutOfBoundsException e) {
            if (log.isDebugEnabled()) {
                log.error("Error while getting the QR code" + e.getMessage());
            }
            return null;
        }
    }

    /**
     * Get the tiqr session id
     */
    protected String getSessionID(String result) {
        try {
            if (!result.contains("Session id: [")) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to find the Session ID");
                }
                return null;
            }
            return result.substring(result.indexOf("Session id: ["),
                    result.indexOf("\" id=\"SessionId\"/>")).replace("Session id: [", "").replace("]", "").trim();
        } catch (IndexOutOfBoundsException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting the Session ID");
            }
            return null;
        }
    }

    /**
     * Get the tiqr end-point
     */
    protected String getTiqrEndpoint(HttpServletRequest request) {
        return TiqrConstants.PROTOCOL + request.getParameter(TiqrConstants.TIQR_CLIENT_IP).trim()
                + ":" + request.getParameter(TiqrConstants.TIQR_CLIENT_PORT).trim();
    }
}
