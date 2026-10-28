<?php
$host = $_GET['host'];
// ruleid: pepper.php.command-injection
system("ping -c 1 " . $host);
// ruleid: pepper.php.command-injection
$out = shell_exec("nslookup " . $_POST['d']);
// ruleid: pepper.php.command-injection
exec("convert {$_FILES['img']['name']} out.png");
// ruleid: pepper.php.command-injection
echo `whois $host`;

// ok: pepper.php.command-injection
system("ping -c 1 " . escapeshellarg($host));
// ok: pepper.php.command-injection
system("uptime");
// ok: pepper.php.command-injection
$p = proc_open(['ping', '-c', '1', $host], $spec, $pipes);
