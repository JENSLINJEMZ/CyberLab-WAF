<?php

class RateLimite {
    private $maxAttempts = 5;
    private $timeWindow = 3600;
    private $attempts = [];
    
    public function isAllowed($ip) {
        $currentTime = time();
        if (!isset($this->attempts[$ip])) {
            $this->attempts[$ip] = [];
        }
        
        // Remove expired attempts
        $this->attempts[$ip] = array_filter($this->attempts[$ip], function($timestamp) use ($currentTime) {
            return ($currentTime - $timestamp) < $this->timeWindow;
        });
        
        // Check if the number of attempts exceeds the limit
        if (count($this->attempts[$ip]) >= $this->maxAttempts) {
            return false; // Rate limit exceeded
        }
        
        // Record the current attempt
        $this->attempts[$ip][] = $currentTime;
        return true; // Allowed
    }
}