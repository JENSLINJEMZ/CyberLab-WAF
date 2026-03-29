<?php

class User {
    public $id;
    public $username;
    public $password;
    public $created;
    public function __construct($id, $username, $password, $created) {
        $this->id = $id;
        $this->username = $username;
        $this->password = $password;
        $this->created = $created;
    }
    public static function getUserByUsername($username) {
        require_once '../database/Database.php';
        $database = new Database();
        $db = $database->getConnection();
        // Fetch user from the database by username
        $query = "SELECT * FROM user WHERE username = :username LIMIT 1";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        if($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            return new User($row['id'], $row['username'], $row['password'], $row['created']);
        } else {
            return null; // User not found
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
            return true; // User exists
        } else {
            return false; // User does not exist
        }
    }
}

