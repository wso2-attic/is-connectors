<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>

<html lang="en">
   <head>
      <meta charset="utf-8">
      <title>Login with SMSOTP</title>
      <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="description" content="">
      <meta name="author" content="">
      <!-- Le styles -->
      <link href="assets/css/bootstrap.min.css" rel="stylesheet">
      <link href="css/localstyles.css" rel="stylesheet">
      <!--[if lt IE 8]>
      <link href="css/localstyles-ie7.css" rel="stylesheet">
      <![endif]-->
      <!-- Le HTML5 shim, for IE6-8 support of HTML5 elements -->
      <!--[if lt IE 9]>
      <script src="assets/js/html5.js"></script>
      <![endif]-->
      <script src="assets/js/jquery-1.7.1.min.js"></script>
      <script src="js/scripts.js"></script>
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


    <div class="container">
         <div class="row">
            <div class="span12">
               <h1>Login with Token</h1>
            </div>
         </div>
      </div>
      <div id="local_auth_div" class="container main-login-container" style="margin-top:10px;">
         <style type="text/css">
            select.input-xlarge {
            height: 25px;
            width: 280px;
            }
            input.input-xlarge {
            height: 25px;
            width: 270px;
            }
         </style>
         <form id="pin_form" name="pin_form" action="../../commonauth"  method="POST">
            <div id="loginTable1" class="identity-box">


        <%
                String loginFailed = request.getParameter("authFailure");
                if (loginFailed != null && "true".equals(loginFailed)) {
            String authFailureMsg = request.getParameter("authFailureMsg");
            if (authFailureMsg != null && "login.fail.message".equals(authFailureMsg)) {
            %>

        <div class="alert alert-error">
            Authentication Failed! Please Retry
            </div>

       <% } }  %>

               <div class="row">
                  <div class="span6">
                     <!-- Token Pin -->
                     <div class="control-group">
                        <label class="control-label" for="password">Code:</label>
                        <input type="password" id='code' name="code" class="input-xlarge" size='30'/>
                     </div>
                     <input type="hidden" name="sessionDataKey"
                        value='<%=request.getParameter("sessionDataKey")%>'/>
                     <div> <input type="submit" value="Authenticate" class="btn btn-primary"></div>
                  </div>
               </div>
            </div>
         </form>
      </div>
   </body>
</html>