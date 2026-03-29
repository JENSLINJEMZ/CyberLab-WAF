<?php

require_once '../database/Database.php';

class ListUsers {
    public static function listUsers() {
        $database = new Database();
        $db = $database->getConnection();
        $query = "SELECT id, username FROM user";
        $stmt = $db->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

$users = ListUsers::listUsers();
header('Content-Type: application/json');
echo json_encode($users);