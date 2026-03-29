<?php
require_once '../database/Database.php';
class  UserDetails{
    public static function Details() {
        $database = new Database();
        $db = $database->getConnection();
        $query = "SELECT * FROM user";
        $stmt = $db->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

$users = UserDetails::Details();
header('Content-Type: application/json');
echo json_encode($users);