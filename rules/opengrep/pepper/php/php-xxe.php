<?php
$xml = file_get_contents('php://input');
// ruleid: pepper.php.xxe
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
$dom = new DOMDocument();
// ruleid: pepper.php.xxe
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
// ruleid: pepper.php.xxe
libxml_disable_entity_loader(false);

// ok: pepper.php.xxe
$safe = simplexml_load_string($xml);
// ok: pepper.php.xxe
$dom->loadXML($xml, LIBXML_NONET);
