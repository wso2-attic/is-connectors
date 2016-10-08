Product: WSO2 IS authenticator for Tiqr
Pre-requisites:

- Maven 3.x
- Java 1.6 or above

Tested Platform: 

- Mac OSx 10.9
- WSO2 IS 5.0.0
- Java 1.7

Do the following:

Build authentication-endpoint and place the jar into <IS_HOME>/repository/deployment/server/webapps

Start the IS server and create Identity provider and service provider in IS via the IS dashboard.

Navigate to tiqr-client/ by issuing the command mentioned below.
cd tiqr-client

Install dependencies using Composer:
curl -sS https://getcomposer.org/installer | php
./composer.phar install

Run from the command line using PHP 5.4+ built-in HTTP server:
php -S <IP>:<port> -t www

Note: tiqr-client project is used to access the tiqr php library. It can be run with the php builtin web server.