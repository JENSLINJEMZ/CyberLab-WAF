<?php

class Route{
    public static function start($controller, $method) {
        $controller = ucfirst($controller) . "Controller";
        $method = $method . "Action";

        if (file_exists("controllers/" . $controller . ".php")) {
            require_once "controllers/" . $controller . ".php";
            $controller_instance = new $controller();
            if (method_exists($controller_instance, $method)) {
                $controller_instance->$method();
            } else {
                echo "Method not found.";
            }
        } else {
            echo "Controller not found.";
        }
    }
}