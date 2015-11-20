<%--
  ~ Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
<%@page import="java.util.ArrayList" %>
<%@page import="java.util.Arrays" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.TiqrConstants" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.TenantDataManager" %>

<fmt:bundle basename="org.wso2.carbon.identity.application.authentication.endpoint.i18n.Resources">

    <%

        request.getSession().invalidate();
        String queryString = request.getQueryString();
        Map<String, String> idpAuthenticatorMapping = null;
        if (request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP) != null) {
            idpAuthenticatorMapping = (Map<String, String>) request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP);
        }

        String errorMessage = "Authentication Failed! Please Retry";
        String enrollmentFailed = "false";

        if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
            enrollmentFailed = "true";

            if (request.getParameter(Constants.AUTH_FAILURE_MSG) != null) {
                errorMessage = request.getParameter(Constants.AUTH_FAILURE_MSG);

                if (errorMessage.equalsIgnoreCase("enrollment.fail.message")) {
                    errorMessage = "Enrollment Failed! Please Retry";
                } else if (errorMessage.equalsIgnoreCase("authentication.fail.message")) {
                    errorMessage = "Authentication Failed! Please Retry";
                }
            }
        }
    %>

    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WSO2 Identity Server</title>

        <link rel="icon" href="images/favicon.png" type="image/x-icon"/>
        <link href="libs/bootstrap_3.3.5/css/bootstrap.min.css" rel="stylesheet">
        <link href="css/Roboto.css" rel="stylesheet">
        <link href="css/custom-common.css" rel="stylesheet">
        <link href="css/custom-tiqr.css" rel="stylesheet">

        <script src="js/scripts.js"></script>
        <script src="assets/js/jquery-1.7.1.min.js"></script>
        <!--[if lt IE 9]>
        <script src="js/html5shiv.min.js"></script>
        <script src="js/respond.min.js"></script>
        <![endif]-->
    </head>

    <body>

    <!-- header -->
    <header class="header header-default">
        <div class="container-fluid"><br></div>
        <div class="container-fluid">
            <div class="pull-left brand float-remove-xs text-center-xs">
                <a href="#">
                    <img src="images/logo-inverse.svg" alt="wso2" title="wso2" class="logo">

                    <h1><em>Identity Server</em></h1>
                </a>
            </div>
        </div>
    </header>

    <!-- page content -->
    <div class="container-fluid body-wrapper">

        <div class="row">
            <div class="col-md-12">

                <!-- content -->
                <div class="container col-xs-10 col-sm-6 col-md-6 col-lg-4 col-centered wr-content wr-login col-centered">
                    <div>
                        <h2 class="wr-title blue-bg padding-double white boarder-bottom-blue margin-none">
                            Authenticating user with Tiqr</h2>
                    </div>
                    <div class="boarder-all ">
                        <div class="clearfix"></div>
                        <div class="padding-double login-form">
                            <div id="alertDiv"></div>
        <%
        if ("true".equals(enrollmentFailed)) {
        %>
        <div id="errorDiv">
            <div class="alert alert-danger" id="error-msg">
                <%=errorMessage%>
            </div>
        </div>
        <% } %>
        <form action="../commonauth" method="post" id="enrollmentForm">
        <%
        if(request.getParameter(TiqrConstants.TIQR_ACTION) != null
                && request.getParameter(TiqrConstants.TIQR_ACTION).equals(TiqrConstants.TIQR_ACTION_AUTHENTICATION)){
        %>
            <div id="authenticationDiv" class="identity-box">
        <%
        } else {
        %>
            <div id="authenticationDiv" class="identity-box" style="display:none;">
        <%
        }
        %>
        </div>
        <%
        if(request.getParameter(TiqrConstants.TIQR_ACTION) != null
                && request.getParameter(TiqrConstants.TIQR_ACTION).equals(TiqrConstants.TIQR_ACTION_AUTHENTICATION)){
        %>
            <div id="enrollmentTable" class="identity-box" style="display:none;">
        <%
        } else {
        %>
            <div id="enrollmentTable" class="identity-box">
        <%
        }
        %>
            <input type="hidden" name="sessionDataKey" value='<%=request.getParameter("sessionDataKey")%>' />
            <!--Username-->
            <div class="col-xs-12 col-sm-12 col-md-12 col-lg-12 form-group">
                <input id="username" name="username" type="text" class="form-control" tabindex="0" placeholder="Username">
            </div>
            <!--Password-->
            <div class="col-xs-12 col-sm-12 col-md-12 col-lg-12 form-group">
                <input id="password" name="password" type="password" class="form-control" tabindex="0" placeholder="password">
            </div>
            <!-- userId -->
            <div class="col-xs-12 col-sm-12 col-md-12 col-lg-12 form-group">
                <input id="userId" name="userId" type="text" class="form-control" tabindex="0" placeholder="User Id">
            </div>
            <!--DisplayName-->
            <div class="col-xs-12 col-sm-12 col-md-12 col-lg-12 form-group">
                <input id="displayName" name="displayName" type="text" class="form-control" tabindex="0" placeholder="Full Name">
            </div>
        <div class="form-actions">
            <input type="button" value="<fmt:message key='go'/>" class="wr-btn grey-bg col-xs-12 col-md-12 col-lg-12 uppercase font-extra-large" id="enroll">
        </div>
<script src="http://code.jquery.com/jquery-1.10.2.js" type="text/javascript"></script>
<script type="text/javascript">
$(document).ready(function() {
	$('#enroll').click(function() {
		$.ajax({
		    url : 'GetQRCode',
		    data : {
		        username : $('#username').val(),
		        password : $('#password').val(),
		        userId : $('#userId').val(),
		        displayName : $('#displayName').val(),
		        clientIP : $('#clientIP').val(),
		        port : $('#port').val(),
		        tiqrAction : "enrollment"
			},
			success : function(responseText) {
			    if(!responseText.startsWith("Failed:")) {
			        document.getElementById("qrCodeDiv").innerHTML = responseText;
			    	document.getElementById('enrollmentTable').style.display = 'none';
    	            document.getElementById('linksDiv').style.display = 'none';
			    }
			    if(responseText.startsWith("Failed:") || $('#sessionId').val() != "") {
			        $('#enrollmentForm').submit();
			    }
			}
		});
	});
});
</script>
<script type="text/javascript">
function showAuthenticationQR() {
if($('#tiqrAction').val() == "authentication" && $('#error').val() != "enrollment.fail.message") {
    $.ajax({
        url : 'GetQRCode',
        data : {
            username : "",
            password : "",
            userId : "",
            displayName : "",
            clientIP : $('#clientIP').val(),
            port : $('#port').val(),
            tiqrAction : "authentication"
        },
        success : function(responseText) {
            if(!responseText.startsWith("Failed:")) {
                document.getElementById("qrCodeDiv").innerHTML = responseText;
			    $('#enrollmentForm').submit();
            } else {
            	document.getElementById('alertDiv').innerHTML = '<div id="alertDiv" class="alert alert-danger">'
            	+ responseText + '</div>';
            }
        }
    });
}
}
$(document).ready(function() {
	$('#showEnrollmentDiv').click(function() {
	    document.getElementById("tiqrAction").value = "enrollment";
	    document.getElementById("error").value = "";
	    document.getElementById('enrollmentTable').style.display = 'inline';
	    document.getElementById('authenticationDiv').style.display = 'none';
    	document.getElementById('enrollmentLinkDiv').style.display = 'none';
	    document.getElementById('qrCodeDiv').innerHTML = '';
	    clearAlert();
	});
	$('#showAuthenticationDiv').click(function() {
	    document.getElementById("tiqrAction").value = "authentication";
	    document.getElementById("error").value = "";
    	document.getElementById('enrollmentTable').style.display = 'none';
    	document.getElementById('linksDiv').style.display = 'none';
    	document.getElementById('authenticationDiv').style.display = 'inline';
		showAuthenticationQR();
    	clearAlert();
    });
});

function clearAlert() {
    document.getElementById('alertDiv').innerHTML = '';
	document.getElementById('errorDiv').innerHTML = '';
}
</script>
		    <%
		        String clientIP = (String) request.getParameter(TiqrConstants.TIQR_CLIENT_IP);
		        String port = (String) request.getParameter(TiqrConstants.TIQR_CLIENT_PORT);
		    	String tiqrAction = (String) request.getParameter(TiqrConstants.TIQR_ACTION);
		    	String error = (String) request.getParameter(Constants.AUTH_FAILURE_MSG);
            %>
	        <input type='hidden' name='clientIP' id='clientIP' value='<%=clientIP%>'/>
	        <input type='hidden' name='port' id='port' value='<%=port%>'/>
	        <input type='hidden' name='tiqrAction' id='tiqrAction' value='<%=tiqrAction%>'/>
	        <input type='hidden' name='error' id='error' value='<%=error%>'/>
        </div>
	<br>
	<div id="qrCodeDiv"></div>
    <div id="linksDiv" align="center">
        <%
        if(tiqrAction.equals("authentication")) { %>
            <div id="enrollmentLinkDiv" style="display:inline-block; float:left">
        <% } else { %>
            <div id="enrollmentLinkDiv" style="display:none; float:left">
        <% } %>
                <a id="showEnrollmentDiv">Enroll a user</a>
            </div><div id="authenticationLinkDiv" style="display:inline-block; float:right">
                <a id="showAuthenticationDiv">Authenticate a user</a>
            </div>
    </div>
    </form>
                            <div class="clearfix"></div>
                        </div>
                    </div>
                    <!-- /content -->

                </div>
            </div>
            <!-- /content/body -->

        </div>
    </div>

    <!-- footer -->
    <footer class="footer">
        <div class="container-fluid">
            <p>WSO2 Identity Server | &copy;
                <script>document.write(new Date().getFullYear());</script>
                <a href="http://wso2.com/" target="_blank"><i class="icon fw fw-wso2"></i> Inc</a>. All Rights Reserved.
            </p>
        </div>
    </footer>
    <script src="libs/jquery_1.11.3/jquery-1.11.3.js"></script>
    <script src="libs/bootstrap_3.3.5/js/bootstrap.min.js"></script>
    </body>
    </html>
</fmt:bundle>