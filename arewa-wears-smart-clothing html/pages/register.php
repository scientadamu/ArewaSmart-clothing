<?php
// Database configuration
$host = 'localhost'; 
$username = 'root'; 
$password = ''; 
$database = 'smart_clothing_system'; 

// Create connection
$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Capture the form data
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm-password'];

    // Basic validation
    if (empty($name) || empty($email) || empty($password) || empty($confirmPassword)) {
        die("All fields are required.");
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format.");
    }

    if ($password !== $confirmPassword) {
        die("Passwords do not match.");
    }

    // Check if the email already exists
    $emailQuery = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $emailQuery->bind_param("s", $email);
    $emailQuery->execute();
    $result = $emailQuery->get_result();

    if ($result->num_rows > 0) {
        die("Email is already registered.");
    }

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Insert into the database
    $sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
    $stmt = $conn->prepare($sql);
    
    if ($stmt === false) {
        die("Prepare failed: " . $conn->error);
    }

    $stmt->bind_param("sss", $name, $email, $hashedPassword);

    if ($stmt->execute()) {
        // Redirect to login page on successful registration
        header("Location: Login.html");
        exit(); // Ensure no further code is executed after the redirect
    } else {
        die("Error: " . $stmt->error);
    }

    // Close the statement
    $stmt->close();
}

// Close connection
$conn->close();
?>
