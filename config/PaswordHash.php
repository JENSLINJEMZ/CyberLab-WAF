<?php

class PasswordHash {
    public static function hash($password) {
        $len = ['cost' => 8];
        return password_hash($password, PASSWORD_BCRYPT, $len);
    }
    public static function verify_hash($password, $hash) {
        return password_verify($password, $hash);
    }
}

//echo PasswordHash::hash("12345678");