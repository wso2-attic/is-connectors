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

$this->data['header'] = $this->t('{authTiqr:tiqr:header_enrollment}');
$this->data['autofocus'] = 'otp';

$this->includeAtTemplateBase('includes/header.php');
if (isset($this->data['errorcode'])) {
    $this->includeAtTemplateBase("authTiqr:includes/inline_error.php");
}
?>

    <h2 class="main"><?php echo $this->t('{authTiqr:tiqr:header_enrollment}'); ?></h2>

<?php if ($this->data['mayCreate']) { ?>

    <form action="#" method="post" name="f">

        <p><?php echo $this->t('{authTiqr:tiqr:intro_enrollment}'); ?></p>
        <?php
        if (!array_key_exists('AuthState', $_REQUEST)) {
            $id = SimpleSAML_Auth_State::saveState($state, sspmod_authTiqr_Auth_Tiqr::STAGEID);
            $_REQUEST['AuthState'] = $id;
            $this->data['stateparams'] = array('AuthState' => $_REQUEST['AuthState']);
        }
        ?>

        <?php
        $sid = SimpleSAML_Session::getSessionFromRequest()->getSessionId();
        ?>
        <input type="hidden" name="SessionId" value="<?php echo 'Session id: [' . $sid . ']'; ?>" id="SessionId"/>

        <p>
            <label style="width: 7em; float:left;" for="userId">
                <?php echo $this->t('{authTiqr:tiqr:label_userid}'); ?>: </label>
            <input id="userId" type="text" tabindex="1" name="userId"
                   value="<?php echo isset($this->data['userId']) ? htmlspecialchars($this->data['userId']) : ''; ?>"/>

        <p><label style="width: 7em; float:left;"
                  for="displayName"><?php echo $this->t('{authTiqr:tiqr:label_displayname}'); ?>: </label>
            <input id="displayName" type="text" tabindex="2" name="displayName"
                   value="<?php echo isset($this->data['displayName']) ? htmlspecialchars($this->data['displayName']) : ''; ?>"/>

        <p><input type="hidden" name="create" value="1"/>
            <br/><strong><?php echo $this->t('{authTiqr:tiqr:important}'); ?></strong>: <?php echo $this->t('{authTiqr:tiqr:qr_youreyesonly}'); ?>

        <p>
            <button type="submit"><?php echo $this->t('{authTiqr:tiqr:go}'); ?></button>
        </p>
        <?php
        if (isset($_POST['action']) and $_REQUEST['action'] == "getStatus") {
            $sid = $_REQUEST['sessionId'];
            ?>
            <input type="hidden" name="enrollmentStatus" value="<?php echo sspmod_authTiqr_Auth_Tiqr::getServer(true)->getEnrollmentStatus($sid); ?>" id="enrollmentStatus"/>
            <?php
        }
        ?>
        <?php
        if (isset($this->data['stateparams'])) {
            foreach ($this->data['stateparams'] as $name => $value) {
                echo('<input type="hidden" name="' . htmlspecialchars($name) . '" value="' . htmlspecialchars($value) . '" id="' . htmlspecialchars($name) . '"/>');
            }
        }
        ?>

    </form>

    <?php

}

$this->includeAtTemplateBase('includes/footer.php');

