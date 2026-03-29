<?php

require_once '../config/db.php';
require_once '../api/register.php';
if ($_SERVER["REQUEST_METHOD"] == "GET") {
    $email = $_GET['email'];
    $password = $_GET['password'];
    $register = new Register();
    $register->registerUser($email, $password);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Register</title>
</head>
<body style="background-color: black;">
    <form action="register.php">
        <input type="email" name="email" placeholder="Email" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Register</button>
    </form>
</body>
</html>
