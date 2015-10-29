<%--
  ~ Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page import="org.wso2.carbon.identity.authenticator.TiqrConstants" %>
<div id="enrollmentTable" class="identity-box">
    <%
        loginFailed = CharacterEncoder.getSafeText(request.getParameter("loginFailed"));
        if (loginFailed != null) {
    %>
    <div class="alert alert-error">
        <fmt:message key='<%=CharacterEncoder.getSafeText(request.getParameter
                ("errorMessage"))%>'/>
    </div>
    <% } %>
    <!-- userId -->
    <div class="control-group">
        <label class="control-label" for="userId"><fmt:message key='userId'/>:</label>
        <div class="controls">
            <input class="input-xlarge" type="text" id='userId' name="userId" style="height:20px"/>
        </div>
    </div>
    <!--DisplayName-->
    <div class="control-group">
        <label class="control-label" for="displayName"><fmt:message key='fullName'/>:</label>

        <div class="controls">
            <input type="text" id='displayName' name="displayName" class="input-xlarge" style="height:20px"/>
            <input type="hidden" name="sessionDataKey" value='<%=CharacterEncoder.getSafeText(request.getParameter("sessionDataKey"))%>'/>
        </div>
    </div>
    <div class="form-actions">
        <input type="button" value="<fmt:message key='go'/>" class="btn btn-primary" id="enroll">
    </div>
<script src="http://code.jquery.com/jquery-1.10.2.js" type="text/javascript"></script>
<script type="text/javascript">
$(document).ready(function() {
	$('#enroll').click(function() {
		$.ajax({
		    url : 'GetQRCode',
			data : {
				userId : $('#userId').val(),
                displayName : $('#displayName').val(),
                clientIP : $('#clientIP').val(),
                port : $('#port').val()
			},
			success : function(responseText) {
			    if(!responseText.startsWith("Failed:")) {
				    document.getElementById("qrCodeDiv").innerHTML = responseText;
				}
                if(responseText.startsWith("Failed:") || $('#sessionId').val() != "") {
                    $('#loginForm').submit();
                }
			}
		});
	});
});
</script>
	<br>
	<div id="qrCodeDiv"></div>
	<%
	String clientIP = (String) request.getParameter(TiqrConstants.TIQR_CLIENT_IP);
	String port = (String) request.getParameter(TiqrConstants.TIQR_CLIENT_PORT);
	%>
	<input type='hidden' name='clientIP' id='clientIP' value='<%=clientIP%>'/>
	<input type='hidden' name='port' id='port' value='<%=port%>'/>
</div>