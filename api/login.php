<?php
include '../config/statuscode.php';
require_once '../config/PaswordHash.php';
include '../config/security/RateLimite.php';

class Login{
    private $id = null;
    private $username = null;
    public function loginUser($username, $password)
    {
        require_once '../database/Database.php';
        $database = new Database();
        $db = $database->getConnection();

        // Check if the user exists in the database
        if($username === null || $password === null) {
            Statuscode::sendApiResponse(null, 400, 'Username and password are required.');
            return "Username and password are required.";
        }
        $query = "SELECT * FROM user WHERE username = :username LIMIT 1";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && PasswordHash::verify_hash($password, $user['password'])) {
            $this->id = $user['id'];
            $this->username = $user['username'];
            Statuscode::sendApiResponse(["id" => $this->id, "username" => $this->username], 200, 'Login successful.');
            return "Login successful.";
        } else {
            Statuscode::sendApiResponse(null, 401, 'Invalid username or password.');
            return "Invalid username or password.";
        }
    }
}

$username = $_REQUEST['username'];
$password = $_REQUEST['password'];
$login = new Login();
$result = $login->loginUser($username, $password);
echo $result;