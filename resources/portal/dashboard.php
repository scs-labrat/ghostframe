<?php
session_start(); // Resume session

// Redirect to login if user isn't logged in
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: index.php');
    exit;
}

// --- Internal Server Info (Hardcoded for CTF) ---
$file_server_name = 'fileserv.targetcorp.local';
$file_server_ip = '10.0.10.50'; // From narrative/compose
$db_server_name = 'db.targetcorp.local';
$db_server_ip = '10.0.10.200'; // From narrative/compose
$wiki_server_name = 'dev-wiki.targetcorp.local';
$wiki_server_ip = '10.0.10.150'; // From narrative/compose
// --- End Internal Server Info ---

$flag_portal_access = 'FLAG{PORTAL_ACCESS_VIA_SQLI}'; // Flag confirming access

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TargetCorp Dashboard</title>
     <style>
        body { font-family: sans-serif; max-width: 800px; margin: 50px auto; }
        .welcome { font-size: 1.2em; margin-bottom: 20px; }
        .server-list { list-style-type: none; padding: 0; }
        .server-list li { background-color: #f0f0f0; margin-bottom: 5px; padding: 8px; border-left: 3px solid #007bff; }
        .flag { margin-top: 20px; padding: 10px; background-color: #e0ffe0; border: 1px solid #a0d0a0; font-family: monospace; }
    </style>
</head>
<body>

    <div style="float: right;">
        <a href="logout.php">Logout</a>
    </div>

    <h2>TargetCorp Internal Dashboard</h2>

    <p class="welcome">Welcome, <?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username']); ?>!</p>

    <h3>Key Internal Systems:</h3>
    <ul class="server-list">
        <li>File Server: <?php echo htmlspecialchars($file_server_name); ?> (<?php echo htmlspecialchars($file_server_ip); ?>) - Status: <span style="color:green;">Online</span></li>
        <li>Database: <?php echo htmlspecialchars($db_server_name); ?> (<?php echo htmlspecialchars($db_server_ip); ?>) - Status: <span style="color:green;">Online</span></li>
        <li>Dev Wiki: <?php echo htmlspecialchars($wiki_server_name); ?> (<?php echo htmlspecialchars($wiki_server_ip); ?>) - Status: <span style="color:green;">Online</span></li>
        <!-- Add more dummy info if desired -->
    </ul>

    <p>This information is confidential.</p>

    <div class="flag">
        Flag obtained via successful login/bypass: <?php echo htmlspecialchars($flag_portal_access); ?>
    </div>

</body>
</html>