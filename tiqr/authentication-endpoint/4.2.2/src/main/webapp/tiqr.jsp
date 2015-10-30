<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<!--
~ Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
~
~ WSO2 Inc. licenses this file to you under the Apache License,
~ Version 2.0 (the "License"); you may not use this file except
~ in compliance with the License.
~ You may obtain a copy of the License at
~
~    http://www.apache.org/licenses/LICENSE-2.0
~
~ Unless required by applicable law or agreed to in writing,
~ software distributed under the License is distributed on an
~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
~ KIND, either express or implied.  See the License for the
~ specific language governing permissions and limitations
~ under the License.
-->
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.CharacterEncoder"%>
<%@ page import="org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="org.wso2.carbon.identity.authenticator.TiqrConstants" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.Constants" %>
<fmt:bundle basename="org.wso2.carbon.identity.application.authentication.endpoint.i18n.Resources">
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Enrollment with WSO2 Identity Server</title>
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="">
        <meta name="author" content="">
        <!-- Le styles -->
        <link href="/authenticationendpoint/assets/css/bootstrap.min.css" rel="stylesheet">
        <link href="/authenticationendpoint/css/localstyles.css" rel="stylesheet">
        <script src="/authenticationendpoint/assets/js/jquery-1.7.1.min.js"></script>
        <script src="/authenticationendpoint/js/scripts.js"></script>
	<style>
	div.different-login-container a.truncate {
	  width: 148px;
	  white-space: nowrap;
	  overflow: hidden;
	  text-overflow: ellipsis;
	}
	</style>
</head>
<body>
    <div class="overlay" style="display:none"></div>
    <div class="header-strip">&nbsp;</div>
    <div class="header-back">
        <div class="container">
            <div class="row">
                <div class="span12">
                    <a class="logo">&nbsp</a>
                </div>
            </div>
        </div>
    </div>
    <div class="header-text"></div>
    <div class="container">
	    <div class="row">
		    <div class="span12">
			    <h1>Enter these details to enroll a new user</h1>
		    </div>
	    </div>
    </div>    
   <%
   String queryString = request.getQueryString();
   String errorMessage = "Authentication Failed! Please Retry";
   String enrollmentFailed = "false";
    if (request.getParameter(Constants.AUTH_FAILURE) != null
            && "true".equals(request.getParameter(Constants.AUTH_FAILURE))) {
        enrollmentFailed = "true";
        if(request.getParameter(Constants.AUTH_FAILURE_MSG) != null){
            errorMessage = (String) request.getParameter(Constants.AUTH_FAILURE_MSG);
            if (errorMessage.equalsIgnoreCase("enrollment.fail.message")) {
                errorMessage = "Authentication Failed! Please Retry";
            }
        }
    }
    %>
    <div id="local_auth_div" class="container main-login-container" style="margin-top:10px;">
        <%
        if ("true".equals(enrollmentFailed)) {
        %>
            <div class="alert alert-error">
                <%=errorMessage%>
            </div>
        <% } %>
        <form action="../../commonauth" method="post" id="enrollmentForm" class="form-horizontal" >
        <div id="enrollmentTable" class="identity-box">
            <input type="hidden" name="sessionDataKey" value='<%=request.getParameter("sessionDataKey")%>' />
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
                    $('#enrollmentForm').submit();
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
        </form>
    </div>
</body>
</html>
</fmt:bundle>