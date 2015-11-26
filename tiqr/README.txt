Product: WSO2 IS authenticator for Tiqr
Pre-requisites:

- Maven 3.x
- Java 1.6 or above

Tested Platform: 

- Mac OSx 10.9
- WSO2 IS 5.1.0-beta
- Java 1.7

Do the following:

1. Build org.wso2.carbon.identity.application.authentication.endpoint and place the jar into <IS_HOME>/repository/deployment/server/webapps

2. Build org.wso2.carbon.identity.application.authentication.endpoint.util and patch the jar into <IS_HOME>/repository/components/patches

3. Put the jars given in https://github.com/Shakila/Tiqr-IS-5.1.0/tree/master/tiqr-authenticator/org.wso2.carbon.identity.authenticator.tiqr/src/main/resources into TIQR_AUTHENTICATOR_HOME>/org.wso2.carbon.identity.authenticator/src/main/resources

4. Patch the jars given in TIQR_AUTHENTICATOR_HOME>/org.wso2.carbon.identity.authenticator/src/main/resources into <IS_HOME>/repository/components/patches

5. Start the IS server and create Identity provider and service provider in IS via the IS console.

6. Navigate to tiqr-client/ by issuing the command mentioned below.
cd tiqr-client

7. Install dependencies using Composer:
curl -sS https://getcomposer.org/installer | php
./composer.phar install

8. Run from the command line using PHP 5.4+ built-in HTTP server:
php -S <IP>:<port> -t www

Note: tiqr-client project is used to access the tiqr php library. It can be run with the php builtin web server.
