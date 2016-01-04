<?php

/**
 * This file is part of simpleSAMLphp.
 * 
 * The authTiqr module is a module adding authentication via the tiqr 
 * project to simpleSAMLphp. It was initiated by SURFnet and 
 * developed by Egeniq.
 *
 * See the README file for instructions and requirements.
 *
 * @author Ivo Jansch <ivo@egeniq.com>
 * 
 * @package simpleSAMLphp
 * @subpackage authTiqr
 *
 * @license New BSD License - See LICENSE file in the tiqr library for details
 * @copyright (C) 2010-2011 SURFnet BV
 *
 */

sspmod_authTiqr_Auth_Tiqr::resetEnrollmentSession();

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'authTiqr:newuser_complete.php');

if (isset($_REQUEST['AuthState'])) {
    $t->data['stateparams'] = array('AuthState' => $_REQUEST['AuthState']);
    $t->data['loginUrl'] = SimpleSAML_Module::getModuleURL('authTiqr/login.php', $t->data['stateparams']);
}
$t->show();
exit();
