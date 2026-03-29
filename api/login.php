<?php

class Login{
    public static function loginUser($email, $password){
        $conn = Database::connect();
        $sql = "SELECT * FROM users WHERE email='$email' AND password='$password'";
        $result = mysqli_query($conn, $sql);
        if (mysqli_num_rows($result) > 0) {
            // echo "Login successful";
            echo  "<h1>" ."Welcome, ". $email . "</h1>";
        } else {
            echo "Invalid email or password";
        }
        mysqli_close($conn);
    }
}