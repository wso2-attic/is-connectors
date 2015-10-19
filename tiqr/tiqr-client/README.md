# tiqrClient
===========

Simple demo project explaining the use of the tiqr php library.

Many shortcuts:

- no dependencies except the tiqr libraries
- uses google chart api instead of phpqrencode (bad idea except for testing/demo purposes!)
- using `error_log` for logging (stdout when using PHP's builtin web server)
- User accounts and state information are stored in `/tmp`.
- Doesn't use more advanced features, like push notifications and step-up authentication.

Goal is to have a simple tiqr demo that can be run with the php builtin web server.

## Install

Install dependencies using Composer:

 	curl -sS https://getcomposer.org/installer | php
	./composer.phar install

Run from the command line using PHP 5.4+ built-in HTTP server:

	php -S ip:port -t www

where ip is an IP address you're tiqr client can connect to (127.0.0.1 won't do if you want to use the tiqr app).
Use 0.0.0.0 to listen on any interface.
Connect your phone to the same WiFi network your demo server is running on to be able to use the demo.
Port is typically 8080 (80 requires root).

## Web browser demo

Point your browser at `http://ip:port/` to start the demo.

## Command Line Client

Alternatively, simulate the tiqr app using curl (in which case you can run this demo on localhost).

### Enrolment

For example, to enrol a new user:

	$ curl http://localhost:8080/enrol.php --data uid=jd --data displayName=John+Doe
	
The generated page will contain a QR code that encodes a tiqr enrolment URL, eg:

	tiqrenroll://http://localhost:8080/tiqr.php?key=somerandomkey

The embedded URL points to tiqr metadata for the new account, intended for the tiqr client:

	$ curl http://localhost:8080/tiqr.php?key=somerandomkey
	{
	    "identity": {
			"displayName": "John Doe",
			"identifier": "jd"
	    },
	    "service": {
			"authenticationUrl": "http://localhost:8080/tiqr.php",
			"displayName": "tiqr demo",
			"enrollmentUrl": "http://localhost:8080/tiqr.php?otp=somerandomotp",
			"identifier": "localhost",
			"infoUrl": "https://www.tiqr.org",
			"logoUrl": "https://demo.tiqr.org/img/tiqrRGB.png",
			"ocraSuite": "OCRA-1:HOTP-SHA1-6:QH10-S"
	    }
	}

The tiqr client will read the metadata, and register a secret with the server:

	$ curl
	  --data operation=register
	  --data secret=3132333435363738393031323334353637383930313233343536373839303132
	   http://localhost:8080/tiqr.php?otp=somerandomotp
	OK

Registration is finished. The new account is stored in the `/tmp` directory:

	$ cat /tmp/jd.json 
	{
		"userId":"jd",
		"displayName":"John Doe",
		"secret":"3132333435363738393031323334353637383930313233343536373839303132"
	}

### Authentication

For authentication, use the login script:	

	$ curl http://127.0.0.1:8000/login.php

The generated page will contain a QR code that encodes a tiqr authentication URL, eg:

	tiqrauth://127.0.0.1/sessionid/challenge/127.0.0.1/version

The tiqr client will generate an OTP based on the challenge and session ID, and post it to the server for authentication.
