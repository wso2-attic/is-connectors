Steps to run

1.  Build the org.wso2.carbon.identity.application.authentication.endpoint and copy the inweboauthenticationendpoint.war 
    to <IS-HOME>/repository/deployment/server/webapps/
    Or unzip the authenticationendpoint.war & copy the inwebo.jsp from inwebo/org.wso2.carbon.identity.authenticator/src/main/resources 
    to <IS-HOME>/repository/deployment/server/webapps/authenticationendpoint

2.  Build the org.wso2.carbon.identity.authenticator & copy the org.wso2.carbon.identity.authenticator.inwebo-1.0.0.jar 
    to <IS-HOME>/repository/components/dropins

3.  Follow the steps in https://docs.wso2.com/display/ISCONNECTORS/Configuring+Inwebo+Authenticator