Product: WSO2 IS authenticator for MePIN
Pre-requisites:

- Maven 3.x
- Java 1.6 or above

Tested Platform: 

- UBUNTU 14.04
- WSO2 IS 5.1.0
- Java 1.7

Do the following:

1. Navigate to authentication-endpoint/org.wso2.carbon.identity.application.authentication.endpoint.mepin and build.

2. Place the mepinauthenticationendpoint.war file into <IS_HOME>/repository/deployment/server/webapps.

3. Navigate to mepin-authenticator/org.wso2.carbon.identity.authenticator.mepin and build.

4. Place the org.wso2.carbon.identity.authenticator.mepin-1.0.0.jar file into <IS_HOME>/repository/components/dropins.

5. Start the IS server and create Identity provider and service provider in IS via the IS console.

