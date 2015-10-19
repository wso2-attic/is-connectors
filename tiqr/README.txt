Clone tiqrClient project from https://github.com/Shakila/tiqrClient.git

tiqrClient project is used to access the tiqr php library. It can be run with the php builtin web server.

Do the following:

Navigate to tiqrClient/ by issuing the command mentioned below.
cd tiqrClient

Install dependencies using Composer:
curl -sS https://getcomposer.org/installer | php
./composer.phar install

Run from the command line using PHP 5.4+ built-in HTTP server:
php -S <IP>:<port> -t www