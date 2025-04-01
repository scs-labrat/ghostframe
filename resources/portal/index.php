<?php
session_start(); // Start session to manage login state

// ---- Configuration ----
// Ideally, read from a config file, but hardcoded for CTF simplicity
$db_host = 'db-internal'; // Service name in Docker Compose
$db_user = 'web_user';
$db_pass = 'SimplePassw0rd';
$db_name = 'targetcorp_db';
// ---- End Configuration ----

$error_message = '';

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // --- Database Connection ---
    $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
    if ($conn->connect_error) {
        // Basic error handling (might reveal too much info in real world)
        $error_message = "Database Connection Error: " . $conn->connect_error;
        // Don't proceed if DB connection fails
    } else {
        // --- Vulnerable Part ---
        // Get username directly from POST without sanitization!
        $username_input = $_POST['username'];
        // Password from POST isn't even used in the vulnerable query logic here
        $password_input = $_POST['password'];

        // Construct the SQL query by directly embedding the username input
        // THIS IS THE VULNERABLE LINE!
        $sql = "SELECT id, username, full_name FROM portal_users WHERE username = '$username_input'";

        // Execute the query
        $result = $conn->query($sql);

        if ($result === false) {
            // Query failed (maybe syntax error from injection?)
             $error_message = "Login Query Failed."; // Keep error generic
             // $error_message = "Login Query Failed: " . $conn->error; // Debugging version (leaks info)
        } elseif ($result->num_rows > 0) {
            // If the query returned ANY rows (SQLi like ' OR '1'='1 -- works here)
            // Consider login successful. Fetch the *first* user returned.
            $user_data = $result->fetch_assoc();

            // Set session variables using data from the DB, not user input
            $_SESSION['loggedin'] = true;
            $_SESSION['user_id'] = $user_data['id'];
            $_SESSION['username'] = $user_data['username']; // Use DB username
            $_SESSION['full_name'] = $user_data['full_name'];

            // Redirect to the dashboard
            header('Location: dashboard.php');
            $conn->close(); // Close connection before exit
            exit;
        } else {
            // No rows returned, standard login failed
            $error_message = 'Invalid username or password.';
        }
        // --- End Vulnerable Part ---

        $conn->close(); // Close DB connection
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TargetCorp Portal Login</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 50px auto; border: 1px solid #ccc; padding: 20px; }
        .error { color: red; margin-bottom: 15px; }
        input[type=text], input[type=password] { width: 95%; padding: 8px; margin-bottom: 10px; }
        input[type=submit] { padding: 10px 15px; background-color: #007bff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h2>TargetCorp Employee Portal</h2>

    <?php if (!empty($error_message)): ?>
        <p class="error"><?php echo htmlspecialchars($error_message); ?></p>
    <?php endif; ?>

    <form method="post" action="index.php">
        <div>
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required>
        </div>
        <div>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required>
        </div>
        <div>
            <input type="submit" value="Login">
        </div>
    </form>

    <!-- Development Note: Input sanitization needed before deployment. -->
    <!-- FLAG{PORTAL_HTML_SOURCE_VIEW} -->

</body>
</html>