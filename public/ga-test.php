<?php

require_once('./include/lib/GoogleAuthenticator.php');

$ga = new GoogleAuthenticator();


/*$secret = $ga->createSecret();
echo "Secret is: ".$secret."\n\n";
*/

$secret = 'UB7A2QLK2M3EQKOF';
echo "Secret is: ".$secret."<br /><br />";

$qrCodeUrl = $ga->getQRCodeGoogleUrl('Blog', $secret);
echo "Google Charts URL for the QR-Code: ".$qrCodeUrl."<br /><br />";



/*
$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";
*/
$oneCode = '807045';

$checkResult = $ga->verifyCode($secret, $oneCode, 2);    // 2 = 2*30sec clock tolerance
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}

?>
