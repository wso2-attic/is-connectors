<?php

require_once __DIR__.'/vendor/joostd/tiqr-server-libphp/library/tiqr/Tiqr/AutoLoader.php';

$options = array(
//    "identifier"      => "demo.tiqr.org",
    "name"            => "tiqr demo",
    "auth.protocol"       => "tiqrauth",
    "enroll.protocol"     => "tiqrenroll",
    "ocra.suite"          => "OCRA-1:HOTP-SHA1-6:QH10-S",
    "logoUrl"         => "https://demo.tiqr.org/img/tiqrRGB.png",
    "infoUrl"         => "https://www.tiqr.org",
    "tiqr.path"           => __DIR__ . "/vendor/joostd/tiqr-server-libphp/library/tiqr",
    'phpqrcode.path' => '.',	// not used
    'zend.path' => __DIR__ . '/vendor/zendframework/zendframework1/library',	// used for push notifications
    "statestorage"        => array("type" => "file"),
    "userstorage"         => array("type" => "file", "path" => "/tmp", "encryption" => array('type' => 'dummy')),
    // "userstorage"         => array("type" => "pdo", 'dsn' => 'sqlite:/tmp/tiqr.sq3', 'table' => 'user', "encryption" => array('type' => 'dummy')),
);


// override options locally. TODO merge with config
if( file_exists(dirname(__FILE__) . "/local_options.php") ) {
    include(dirname(__FILE__) . "/local_options.php");
} else {
    error_log("no local options found");
}


$options["devicestorage"]   = array(
    "type"  => "tokenexchange",
    "url"   => "https://tx.tiqr.org/tokenexchange/",
    "appid" => "tiqr"
);

$autoloader = Tiqr_AutoLoader::getInstance($options); // needs {tiqr,zend,phpqrcode}.path
$autoloader->setIncludePath();

$userStorage = Tiqr_UserStorage::getStorage($options['userstorage']['type'], $options['userstorage']);

function base() {
    $proto = "http://";
    return $proto . $_SERVER['HTTP_HOST'];
    return $baseUrl;
}

function generate_id($length = 8) {
    $chars = "0123456789";
    $count = mb_strlen($chars);
    for ($i = 0, $result = ''; $i < $length; $i++) {
        $index = rand(0, $count - 1);
        $result .= mb_substr($chars, $index, 1);
    }
    return $result;
}
