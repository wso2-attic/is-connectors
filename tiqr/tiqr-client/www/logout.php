<?php

include('../options.php');

session_start();
$tiqr = new Tiqr_Service($options);
$sid = session_id();
$tiqr->logout($sid);
header("Location: /index.php");
