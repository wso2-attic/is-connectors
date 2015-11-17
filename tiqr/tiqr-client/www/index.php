<?php

include('../options.php');

session_start();

$tiqr = new Tiqr_Service($options);
$sid = session_id();

if( isset($_POST['action']) and $_POST['action'] == "getAuthenticatedUser" ) {
    // return authenticated user
    $sessId = $_POST['sessId'];
    $userdata = $tiqr->getAuthenticatedUser($sessId);
} else {
    $userdata = $tiqr->getAuthenticatedUser($sid);
}

if( is_null($userdata) )
	echo "<a href='login.php'>login</a>";
else {
	echo "<a href='logout.php'>logout</a> | <a href='login.php?push'>push</a>";
    echo "<p>Hello $userdata.</p>";
}