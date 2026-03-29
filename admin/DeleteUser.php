<?php
require_once '../config/statuscode.php';
class DeleteUser {
    public static function delete($username) {
        require_once '../database/Database.php';
        $database = new Database();
        $db = $database->getConnection();
        // Delete user from the database
        $query = "DELETE FROM user WHERE username = :username";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':username', $username);
        if($stmt->execute()) {
            Statuscode::sendApiResponse(["username" => $username], 200, 'User deleted successfully.');
            return "User deleted successfully.";
        } else {
            Statuscode::sendApiResponse([], 400, 'Error deleting user.');
            return "Error deleting user.";
        }
    }
}

$username = $_REQUEST['username'];
$result = DeleteUser::delete($username);
echo $result;