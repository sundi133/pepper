<?php
$page = $_GET['page'];
// ruleid: pepper.php.code-injection
include "pages/" . $page . ".php";
// ruleid: pepper.php.code-injection
require_once($_REQUEST['module']);
// ruleid: pepper.php.code-injection
eval('$x = ' . $_POST['expr'] . ';');
// ruleid: pepper.php.code-injection
call_user_func($_GET['fn'], $arg);
$fn = $_GET['cb'];
// ruleid: pepper.php.code-injection
$fn();

// ok: pepper.php.code-injection
include "pages/" . basename($page) . ".php";
// ok: pepper.php.code-injection
include __DIR__ . "/header.php";
// ok: pepper.php.code-injection
call_user_func('strtolower', $_GET['s']);

$importers = ['wp' => ['WordPress', 'desc', 'wp_import']];
// ok: pepper.php.code-injection
call_user_func($importers[$_GET['importer']][2]);

class AiController
{
    public function ask(Request $request)
    {
        // ok: pepper.php.code-injection
        $id = $request->input('conversation_id');
        // ok: pepper.php.code-injection
        $raw = file_get_contents('php://input');
    }
}
