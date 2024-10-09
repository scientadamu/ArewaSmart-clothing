<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', 'php_errors.log');

// Database configuration
$host = 'localhost';  // or your DB server address
$dbname = 'smart_clothing_system';  // Name of the database
$username = 'root';  // Your MySQL username
$password = '';      // Your MySQL password

// Establish a database connection
$conn = new mysqli($host, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed: ' . $conn->connect_error]));
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get email and password from form
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Prepare and bind SQL statement to check email
    $stmt = $conn->prepare("SELECT password FROM users WHERE email = ?");
    if (!$stmt) {
        error_log("Statement preparation failed: " . $conn->error);
        echo json_encode(['status' => 'error', 'message' => 'Database error']);
        exit;
    }

    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    // If user exists
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        // Verify password
        if (password_verify($password, $hashed_password)) {
            // Store the user's email in the session
            $_SESSION['email'] = $email;
            
            // Redirect to landing page
            header("Location: landing.html");
            exit(); // Ensure no further code is executed
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
    }

    $stmt->close();
}

$conn->close();
?>
