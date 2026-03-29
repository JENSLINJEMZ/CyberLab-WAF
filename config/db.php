<?php

class Database{
    public static function connect(){
        $host = 'localhost';
        $dbname = 'cyberlab';
        $username = 'cyberuser';
        $password = 'cyberpass';
        $conn = mysqli_connect($host, $username, $password, $dbname);
        if (!$conn) {
            die("Connection failed: " . mysqli_connect_error());
        }
        echo "Connected successfully";
        return $conn;
    }
}

Database::connect();