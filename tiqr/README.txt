Product: WSO2 IS authenticator for Tiqr
Pre-requisites:

- Maven 3.x
- Java 1.6 or above

Tested Platform: 

- Mac OSx 10.9
- WSO2 IS 5.1.0
- Java 1.7

Do the following:

Deploying and Configuring Tiqr artifacts:
1. Navigate to authentication-endpoint/org.wso2.carbon.identity.application.authentication.endpoint.tiqr and build.

2. Place org.wso2.carbon.identity.application.authentication.endpoint.tiqr war into <IS_HOME>/repository/deployment/server/webapps.

3. Navigate to tiqr-authenticator/org.wso2.carbon.identity.authenticator.tiqr and build.

4. Place org.wso2.carbon.identity.authenticator.tiqr jar into <IS_HOME>/repository/components/dropins.

5. Start the IS server and create Identity provider and service provider in IS via the IS console.

Configuring the Tiqr app:
6. For updating the dependencies: Navigate to tiqr-client/ and install dependencies using Composer.
curl -sS https://getcomposer.org/installer | php
./composer.phar install

7. Run from the command line using PHP 5.4+ built-in HTTP server:
php -S <IP>:<port> -t www

Note: tiqr-client project is used to access the tiqr php library. It can be run with the php builtin web server.
      You can skip step 6.
