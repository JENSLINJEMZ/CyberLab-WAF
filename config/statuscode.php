<?php 
class Statuscode{
    public static function sendApiResponse($data, $statusCode, $message) {
        // Prevent output before headers
        if (ob_get_level()) ob_clean();

        // Set the HTTP status code
        http_response_code($statusCode);

        // Set headers
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');

        // Prepare response
        $response = [
            'status' => $statusCode,
            'message' => $message,
            'data' => $data
        ];

        echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }
}
// Usage
// $sta = new Statuscode();
// $sta->sendApiResponse(['id' => 1, 'name' => 'John'], 200, 'User retrieved successfully');
// $sta->sendApiResponse(null, 404, 'User not found');