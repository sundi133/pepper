<?php
$id = $_GET['id'];
// ruleid: pepper.php.sql-injection
$r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
// ruleid: pepper.php.sql-injection
$pdo->query("SELECT * FROM users WHERE name = '{$_POST['name']}'");
// ruleid: pepper.php.sql-injection
$wpdb->get_results("SELECT * FROM wp_posts WHERE author = '" . $_REQUEST['a'] . "'");

// ok: pepper.php.sql-injection
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
// ok: pepper.php.sql-injection
$stmt->execute([$id]);
// ok: pepper.php.sql-injection
mysqli_query($conn, "SELECT * FROM users WHERE id = " . (int) $_GET['id']);
// ok: pepper.php.sql-injection
mysqli_query($conn, "SELECT * FROM users WHERE n = '" . mysqli_real_escape_string($conn, $_GET['n']) . "'");
// ok: pepper.php.sql-injection
$wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts WHERE author = %s", $_GET['a']));

class UserController
{
    public function search(Request $request)
    {
        $q = $request->input('q');
        // ruleid: pepper.php.sql-injection
        DB::select("SELECT * FROM users WHERE name LIKE '%$q%'");
        // ruleid: pepper.php.sql-injection
        User::query()->whereRaw("email = '" . $request->get('email') . "'")->get();
        // ok: pepper.php.sql-injection
        DB::select('SELECT * FROM users WHERE name = ?', [$q]);
        // ok: pepper.php.sql-injection
        User::where('email', $request->get('email'))->get();
    }
}
