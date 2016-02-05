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
<%@page import="java.util.ArrayList" %>
<%@page import="java.util.Arrays" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
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
        String authenticationFailed = "false";

        if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
            authenticationFailed = "true";

            if (request.getParameter(Constants.AUTH_FAILURE_MSG) != null) {
                errorMessage = request.getParameter(Constants.AUTH_FAILURE_MSG);

                 if (errorMessage.equalsIgnoreCase("authentication.fail.message")) {
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

        <script src="js/scripts.js"></script>
        <script src="assets/js/jquery-1.7.1.min.js"></script>
	<script src="https://mepin.com/javascripts/mepinlogin.js"></script>
        <!--[if lt IE 9]>
        <script src="js/html5shiv.min.js"></script>
        <script src="js/respond.min.js"></script>
        <![endif]-->
    </head>

    <body onload="getLoginDiv()">

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
                            Authenticating with MePIN &nbsp;&nbsp;<a href="https://www.mepin.com/" target="blank"><img src="images/mepin.png" width="50" height="50"/></a></h2>

                    </div>
                    <div class="boarder-all ">
                        <div class="clearfix"></div>
                        <div class="padding-double login-form">
<div id="errorDiv"></div>
  <%
        if ("true".equals(authenticationFailed)) {
        %>
            <div class="alert alert-danger" id="failed-msg">
                <%=errorMessage%>
            </div>
        <% } %>
<form action="../commonauth" method="post" id="enrollmentForm">
<div id="enrollmentTable" class="identity-box">
            <input type="hidden" name="sessionDataKey" value='<%=request.getParameter("sessionDataKey")%>' />
            <div id="loginDiv" style="display:none">
            <!--Username-->
            <div class="col-xs-12 col-sm-12 col-md-12 col-lg-12 form-group">
                <input id="username" name="username" type="text" class="form-control" tabindex="0" placeholder="Username" data-toggle="tooltip" title="The username">
            </div>
            <!--Password-->
            <div class="col-xs-12 col-sm-12 col-md-12 col-lg-12 form-group">
                <input id="password" name="password" type="password" class="form-control" tabindex="0" placeholder="password" data-toggle="tooltip" title="The password">
            </div>
            </div>
         <div class="form-actions">
             <input type="button" value="Link with MePIN" class="wr-btn grey-bg col-xs-12 col-md-12 col-lg-12 lowercase font-extra-large" id="link">
         </div>
         <span style="margin-top: 20px; line-height:0.1px; background:white;">&nbsp;</span>
         <div class="form-actions">
             <input type="button" value="Login with MePIN" class="wr-btn grey-bg col-xs-12 col-md-12 col-lg-12 lowercase font-extra-large" id="go">
         </div>

	<%
	    String applicationId = (String) request.getParameter("applicationId");
	    String callbackUrl = (String) request.getParameter("callbackUrl");
	    String sessionDataKey = (String) request.getParameter("sessionDataKey");
	    String isSecondStep = (String) request.getParameter("isSecondStep");
        %>
	    <input type='hidden' name='applicationId' id='applicationId' value='<%=applicationId%>'/>
	    <input type='hidden' name='callbackUrl' id='callbackUrl' value='<%=callbackUrl%>'/>
	    <input type='hidden' name='sessionDataKey' id='sessionDataKey' value='<%=sessionDataKey%>'/>
            <input type='hidden' name='isSecondStep' id='isSecondStep' value='<%=isSecondStep%>'/>
	    <input type='hidden' name='mepinLogin' id='mepinLogin' value='mepinLogin'/>
</div>
</form>
<script>
function getLoginDiv() {
    var isSecondStep = document.getElementById("isSecondStep").value;
    if(isSecondStep == "false") {
        document.getElementById('loginDiv').style.display = 'inline';
    }
}
$(document).ready(function(){
   $('[data-toggle="tooltip"]').tooltip();
});
</script>
  <div id="loginTable" class="identity-box"></div>
<script src="http://code.jquery.com/jquery-1.10.2.js" type="text/javascript"></script>
    <script type="text/javascript">
    $(document).ready(function() {
    	$('#link').click(function() {
    	var authHeader = btoa(document.getElementById("username").value+":"+document.getElementById("password").value);
    	var applicationId = document.getElementById("applicationId").value;
    	var callbackUrl = document.getElementById("callbackUrl").value;
    	var sessionDataKey = document.getElementById("sessionDataKey").value;
        var isSecondStep = document.getElementById("isSecondStep").value;
    	    if(username!="" && password!="") {
    	        document.getElementById('errorDiv').innerHTML = '';
		document.getElementById('enrollmentTable').style.display = 'none';
    	        document.getElementById('loginTable').innerHTML = '<font style="font-family: Times New Roman, Times, serif; font-size: 20px; color: #006666;">To link with MePIN click </font><div style="float:right;" class="mepin-link" data-theme="light" data-layout="standard" data-applicationid="'+applicationId+'" data-cburl="'+callbackUrl+'?sessionDataKey='+sessionDataKey+'&authHeader='+authHeader+'&isSecondStep='+isSecondStep+'"></div>';
    	    } else {
    	         document.getElementById('errorDiv').innerHTML = '<div class="alert alert-danger" id="error-msg">Invalid username or password</div>';
    	    }
    	});
    });
    </script>
    <script type="text/javascript">
    $(document).ready(function() {
    	$('#go').click(function() {
        var isSecondStep = document.getElementById("isSecondStep").value;
    	if(isSecondStep == "true") {
            $('#enrollmentForm').submit();
        } else {
    	var username = document.getElementById("username").value;
    	var password = document.getElementById("password").value;
    	if(username!="" && password!="") {
    	    $('#enrollmentForm').submit();
            document.getElementById('errorDiv').innerHTML = '';
        } else {
            document.getElementById('errorDiv').innerHTML = '<div class="alert alert-danger" id="error-msg">Invalid username or password</div>';
        }
        }
    	});
    });
    </script>
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