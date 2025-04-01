<?php
session_start(); // Resume the session

// Unset all session variables
$_SESSION = array();

// Destroy the session cookie (if exists)
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Finally, destroy the session.
session_destroy();

// Redirect back to the login page
header('Location: index.php');
exit;
?>