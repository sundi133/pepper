<?php
$name = $_GET['name'];
// ruleid: pepper.php.xss
echo "<h1>Hello " . $name . "</h1>";
// ruleid: pepper.php.xss
echo $_SERVER['PHP_SELF'];
// ruleid: pepper.php.xss
print "<p>" . $_POST['comment'] . "</p>";
// ruleid: pepper.php.xss
die("Unknown user: " . $_REQUEST['u']);

// ok: pepper.php.xss
echo "<h1>Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</h1>";
// ok: pepper.php.xss
echo "Page " . (int) $_GET['page'];
// ok: pepper.php.xss
echo esc_html($_GET['q']);
// ok: pepper.php.xss
echo "static text";
// ok: pepper.php.xss
echo number_format_i18n($_GET['count']);
// ok: pepper.php.xss
echo count($_POST['items']);
