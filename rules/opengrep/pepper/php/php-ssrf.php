<?php
$url = $_GET['url'];
// ruleid: pepper.php.ssrf
$ch = curl_init($url);
// ruleid: pepper.php.ssrf
curl_setopt($ch, CURLOPT_URL, $_POST['webhook']);
// ruleid: pepper.php.ssrf
$client->request('GET', $url);

// ok: pepper.php.ssrf
curl_setopt($ch, CURLOPT_URL, "https://api.example.com/users/" . urlencode($url));
// ok: pepper.php.ssrf
curl_setopt($ch, CURLOPT_URL, "https://api.example.com/users/" . $url);
// ok: pepper.php.ssrf
$ch2 = curl_init("https://api.example.com/health");
