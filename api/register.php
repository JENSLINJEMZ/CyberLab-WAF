<?php
include '../config/statuscode.php';
require_once '../config/PaswordHash.php';
require_once '../api/User.php';
class Register{
    

    public function __construct($username = null) {
        null;
    }
    public static function register($username, $password) {
        require_once '../database/Database.php';
        $database = new Database();
        $db = $database->getConnection();
        if($username === null || $password === null) {
            Statuscode::sendApiResponse(null, 400, 'Username and password are required.');
            return "Username and password are required.";
        }
        if(User::checkUserExists($username)) {
            Statuscode::sendApiResponse(null, 409, 'User already exists.');
            return "User already exists.";
        }
        else{
            $password = PasswordHash::hash($password);
            $query = "INSERT INTO user(username, password,created) VALUES (:username, :password, NOW())";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':password', $password);
            if($stmt->execute()) {
                Statuscode::sendApiResponse(["username" => $username], 201, 'User registered successfully.');
                return "User registered successfully.";
            } else {
                Statuscode::sendApiResponse([], 400, 'Error registering user.');
                return "Error registering user.";
            }
        }
        
    }
    public static function checkUserExists($username) {
        require_once '../database/Database.php';
        $database = new Database();
        $db = $database->getConnection();
        // Check if the user exists in the database
        $query = "SELECT * FROM user WHERE username = :username LIMIT 1";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        if($stmt->fetch(PDO::FETCH_ASSOC)) {
            echo "User already exists.";
            return true; // User exists
        } else {
            return false; // User does not exist
        }
    }
}


$username = $_REQUEST['username'];
$password = $_REQUEST['password'];
$result = Register::register($username, $password);
echo $result;