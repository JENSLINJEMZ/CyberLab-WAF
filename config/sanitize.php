<?php

class sanitize{
    public static function sanitize_input($data) {
        $data = trim($data); // Remove whitespace from the beginning and end
        $data = stripslashes($data); // Remove backslashes
        $data = htmlspecialchars($data); // Convert special characters to HTML entities
        return $data;
    }
    public static function email_sanitize($email) {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL); // Remove all illegal characters from email
        return $email;
    }
}

