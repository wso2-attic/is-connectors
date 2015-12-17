<?php

include('../options.php');

$tiqr = new Tiqr_Service($options);

session_start();
$sid = session_id();

if( isset($_GET['done']) ) {
    $tiqr->resetEnrollmentSession($sid);
    error_log("[$sid] reset enrollment");
    exit();
}

if( isset($_GET['status']) ) {
    $status = $tiqr->getEnrollmentStatus($sid);
    error_log("[$sid] status is $status");
    echo $status;
    exit();
}

if( isset($_POST['action']) and $_POST['action'] == "getStatus" ) {
    // return enrollment status
    $sessId = $_POST['sessId'];
    $status = $tiqr->getEnrollmentStatus($sessId);
    echo "Enrolment status: $status";
}

if( isset($_POST['uid']) and isset($_POST['displayName'])) {
    // starting a new enrollment session
    $uid = $_POST['uid'];
    $displayName = $_POST['displayName'];
    error_log("[$sid] uid is $uid and displayName is $displayName");
    $key = $tiqr->startEnrollmentSession($uid, $displayName, $sid);
    error_log("[$sid] started enrollment session key $key");
    $metadataURL = base() . "/tiqr.php?key=$key";
    error_log("[$sid] generating QR code for metadata URL $metadataURL");
    $url = $tiqr->generateEnrollString($metadataURL);
    $qr = "https://chart.googleapis.com/chart?chs=300x300&cht=qr&chl=" . $url;
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
    <script type="text/JavaScript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.3.2/jquery.min.js"></script>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery.qrcode/1.0/jquery.qrcode.min.js"></script>
    <script type="text/javascript">
        const idle        = "<?php echo Tiqr_Service::ENROLLMENT_STATUS_IDLE ?>";
        const initialized = "<?php echo Tiqr_Service::ENROLLMENT_STATUS_INITIALIZED ?>";
        const retrieved   = "<?php echo Tiqr_Service::ENROLLMENT_STATUS_RETRIEVED ?>";
        const processed   = "<?php echo Tiqr_Service::ENROLLMENT_STATUS_PROCESSED ?>";
        const finalized   = "<?php echo Tiqr_Service::ENROLLMENT_STATUS_FINALIZED ?>";

        function enrolStatus() {
            const self = "<?php echo $_SERVER['PHP_SELF']; ?>";
            jQuery.get( self + '?status', function(status) {
                switch(status) {
                    case idle:
                        $( "span.status-container" ).html( "idle" );
                        alert("Enrol timeout. Please try again by refreshing this page.");
                        break;
                    case initialized:
                        $( "span.status-container" ).html( "initialized" );
                        window.setTimeout(enrolStatus, 1500);
                        break;
                    case retrieved:
                        $( "span.status-container" ).html( "retrieved" );
                        $( "img" ).hide( "slow" );
                        window.setTimeout(enrolStatus, 1500);
                        break;
                    case processed:
                        $( "span.status-container" ).html( "processed" );
                        window.setTimeout(enrolStatus, 1500);
                        break;
                    case finalized:
                        $( "span.status-container" ).html( "finalized" );
                        jQuery.get( self + '?done', function(dummy) {
                            ;
                        });
                        break;
                    default:
                        $( "span.status-container" ).html( status );
                        alert(status);
                }
            });
        }
    </script>
</head>
<body>
<?php if(!isset($_POST['action']) and $_POST['action'] != "getStatus"): ?>
<p>Status is <span class="status-container">idle</span>.</p>

<?php if( !isset($_POST['uid']) or !isset($_POST['displayName']) ): ?>
    <form method='POST'>
        uid:        <input name="uid"/>
        displayName <input name="displayName"/>
        <input type="submit"/>
    </form>
<?php else: ?>
    <div id="qrcode"></div>
    <script type="text/javascript">
        var url = '<?php echo $url; ?>';
        new QRCode("qrcode", {
            text: url,
            correctLevel : QRCode.CorrectLevel.L
        });
    </script>
    <script type="text/javascript">
        jQuery(document).ready(enrolStatus);
    </script>
    <input type="hidden" name="SessionId" value='<?php echo "Session id: [".$sid."]"; ?>'/>
    <img alt="QR" src='<?php echo $qr; ?>'/>
<?php endif; ?>
<?php endif; ?>

</body>
</html>
