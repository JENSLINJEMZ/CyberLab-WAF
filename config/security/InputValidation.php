<?php

class InputValidation {
    public static function validateUsername($username) {
        if (empty($username)) {
            return "Username is required.";
        }
        if (!preg_match("/^[a-zA-Z0-9_]+$/", $username)) {
            return "Username can only contain letters, numbers, and underscores.";
        }
        return null; // No validation errors
    }

    public static function validatePassword($password) {
        if (empty($password)) {
            return "Password is required.";
        }
        if (strlen($password) < 6) {
            return "Password must be at least 6 characters long.";
        }
        return null; // No validation errors
    }
    public static function EmailValidation($email){
        $allow = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "aol.com",
            "icloud.com",
            "mail.com",
            "zoho.com",
            "protonmail.com",
        ];
        $domain = substr($email, strrpos($email, '@') + 1);
        if (!in_array($domain, $allow)) {
            return "Email domain is not allowed.";
        }
        return null; // No validation errors
    }
}
