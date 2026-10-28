<?php
// ruleid: pepper.php.insecure-deserialization
$prefs = unserialize($_COOKIE['prefs']);
// ruleid: pepper.php.insecure-deserialization
$obj = unserialize(base64_decode($_POST['state']));

// ok: pepper.php.insecure-deserialization
$data = unserialize($_COOKIE['prefs'], ['allowed_classes' => false]);
// ok: pepper.php.insecure-deserialization
$json = json_decode($_COOKIE['prefs'], true);
// ok: pepper.php.insecure-deserialization
$cached = unserialize(file_get_contents('/var/cache/app.bin'));
