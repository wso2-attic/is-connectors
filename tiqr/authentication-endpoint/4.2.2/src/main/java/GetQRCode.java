
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.authenticator.TiqrConstants;

@WebServlet("/GetQRCode")
public class GetQRCode extends HttpServlet {
    private static Log log = LogFactory.getLog(GetQRCode.class);
    private static final long serialVersionUID = 1L;

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("userId").trim();
        String displayName = request.getParameter("displayName").trim();
        String res = "";
        if (!StringUtils.isEmpty(userId) && !StringUtils.isEmpty(displayName)) {
            String enrolUserResponse = enrolUser(request);
            String qrCode = getQrCode(enrolUserResponse);
            res = qrCode;
            String sessionId = getSessionID(enrolUserResponse);
            res = res + "<input type='hidden' name='sessionId' id='sessionId' value='" + sessionId + "'/>";
            response.setContentType("text/plain");
        } else {
            res = TiqrConstants.INVALID_INPUT;
        }
        response.getWriter().write(res);
    }

    /**
     * Connect with the tiqr client
     */
    private String enrolUser(HttpServletRequest request) {
        String tiqrEP = getTiqrEndpoint(request);
        String urlToEntrol = tiqrEP + "/enrol.php";
        String userId = request.getParameter(TiqrConstants.ENROLL_USERID);
        String diaplayName = request.getParameter(TiqrConstants.ENROLL_DISPLAYNAME);
        if (!StringUtils.isEmpty(userId) && !StringUtils.isEmpty(diaplayName)) {
            String formParameters = "uid=" + userId + "&displayName=" + diaplayName;
            String result = sendRESTCall(urlToEntrol, "", formParameters, TiqrConstants.HTTP_POST);
            if (result.startsWith("Failed:")) {
                if (log.isDebugEnabled()) {
                    log.error("Unable to find QR code");
                }
                return null;
            }
            return result;
        } else {
            if (log.isDebugEnabled()) {
                log.error("Required parameters should be given");
            }
            return null;
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
            }
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed: " + e.getMessage());
            }
            return "Failed: " + e.getMessage();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed: " + e.getMessage());
            }
            return "Failed: " + e.getMessage();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed: " + e.getMessage());
            }
            return "Failed: " + e.getMessage();
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
            if (!result.contains("<img") || !result.contains("</body>")) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to find QR code");
                }
                return null;
            }
            if (log.isDebugEnabled()) {
                log.debug("QR code is displayed");
            }
            return result.substring(result.indexOf("<img"), result.indexOf("</body>"));
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
                    result.indexOf("'/>")).replace("Session id: [", "").replace("]", "").trim();
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
        return "http://" + request.getParameter(TiqrConstants.TIQR_CLIENT_IP).trim()
                + ":" + request.getParameter(TiqrConstants.TIQR_CLIENT_PORT).trim();
    }
}
