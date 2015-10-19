<?php

include('../options.php');

session_start();

$tiqr = new Tiqr_Service($options);
$sid = session_id();

$userdata = $tiqr->getAuthenticatedUser($sid);

if( is_null($userdata) )
	echo "<a href='login.php'>login</a>";
else {
	echo "<a href='logout.php'>logout</a> | <a href='login.php?push'>push</a>";
    echo "<p>Hello $userdata.</p>";
}