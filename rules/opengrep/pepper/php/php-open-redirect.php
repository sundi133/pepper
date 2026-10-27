<?php
$next = $_GET['next'];
// ruleid: pepper.php.open-redirect
header("Location: " . $next);
// ruleid: pepper.php.open-redirect
header('Location: ' . $_POST['return']);
// ruleid: pepper.php.open-redirect
wp_redirect($_REQUEST['redirect_to']);

// ok: pepper.php.open-redirect
header("Location: /profile.php?tab=" . urlencode($_GET['tab']));
// ok: pepper.php.open-redirect
header("Location: /dashboard");
// ok: pepper.php.open-redirect
header("Content-Type: " . "text/html");
// ok: pepper.php.open-redirect
wp_safe_redirect($_REQUEST['redirect_to']);
// ok: pepper.php.open-redirect
wp_redirect(admin_url('tools.php?' . $_SERVER['QUERY_STRING']));

class AuthController
{
    public function login(Request $request)
    {
        // ruleid: pepper.php.open-redirect
        return redirect()->away($request->input('next'));
    }
}
