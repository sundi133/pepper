<?php
$file = $_GET['file'];
// ruleid: pepper.php.path-traversal
echo file_get_contents("/var/www/uploads/" . $file);
// ruleid: pepper.php.path-traversal
readfile($_REQUEST['doc']);
// ruleid: pepper.php.path-traversal
unlink("/tmp/" . $_POST['name']);
// ruleid: pepper.php.path-traversal
move_uploaded_file($_FILES['f']['tmp_name'], "uploads/" . $_FILES['f']['name']);

// ok: pepper.php.path-traversal
echo file_get_contents("/var/www/uploads/" . basename($file));
// ok: pepper.php.path-traversal
move_uploaded_file($_FILES['f']['tmp_name'], "uploads/" . basename($_FILES['f']['name']));
// ok: pepper.php.path-traversal
$cfg = file_get_contents(__DIR__ . "/config.json");

$base = realpath("/var/www/uploads");
$full = realpath($base . "/" . $_GET['p']);
if ($full === false || !str_starts_with($full, $base . DIRECTORY_SEPARATOR)) {
    http_response_code(403);
    exit;
}
// ok: pepper.php.path-traversal
readfile($full);
