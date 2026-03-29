<?php
require_once '../config/db.php';
require_once '../api/login.php';
if ($_SERVER["REQUEST_METHOD"] == "GET") {
    $email = $_GET['email'];
    $password = $_GET['password'];
    $login = new Login();
    $login->loginUser($email, $password);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Login</title>
</head>
<body>
    <form action="login.php" method="get">
        <input type="email" name="email" placeholder="Email" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>