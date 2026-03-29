<?php

session_start();
require_once 'config/security/fingerprint.php';

header('Content-Type: application/json');

// try {
//     $fingerprint = new DeviceIntelligence();
//     $data = $fingerprint->analyze();
//     echo json_encode([
//         'success' => true,
//         'data'    => $data,
//     ]);
    

// } catch (Throwable $e) {
//     http_response_code(500);
//     echo json_encode([
//         'success' => false,
//         'error'   => $e->getMessage(),
//     ]);
// }

class loginTest {
    public $db;
    public $id,$user_id,$session_id,$ip_address,$user_agent;
    public $devicetype,$country,$event_type,$endpoint,$method,$status_code;
    public $is_success,$failed_reason,$created_at,$last_seen_at;

    public function __construct() {
        $fingerprint = new DeviceIntelligence();
        $data = $fingerprint->analyze();
        $this->id = NULL;
        $this->user_id = 1;
        $this->session_id = session_id();
        $this->ip_address = $data['network']['ip'];
        $this->user_agent = $data['device']['user_agent'];
        $this->devicetype = $data['device']['type'];
        $this->country = $data['geolocation']['country'];
        $this->event_type = "login";
        $this->endpoint = $data['request']['uri'];
        $this->method = $data['request']['method'];
        $this->status_code = $data['status_code'];
        $this->is_success = 1;
        $this->failed_reason = $data['failed_reason'];
        $this->created_at = $data['created_at'];
        $this->last_seen_at = $data['last_seen_at'];
    }

    public function setfingerprint() {
        require_once 'database/Database.php';
        $database = new Database();
        $this->db = $database->getConnection();
        $query = "INSERT INTO `footprints` (`id`, `user_id`, `session_id`, `ip_address`, `useragent`, `devicetype`, `country`, `event_type`, `endpoint`, `method`, `statuscode`, `is_success`, `failed_reason`, `created_at`, `last_seen_at`) VALUES (:id, :user_id, :session_id, :ip_address, :user_agent, :devicetype, :country, :event_type, :endpoint, :method, :status_code, :is_success, :failed_reason, :created_at, :last_seen_at)";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(':id', $this->id);
        $stmt->bindParam(':user_id', $this->user_id);
        $stmt->bindParam(':session_id', $this->session_id);
        $stmt->bindParam(':ip_address', $this->ip_address);
        $stmt->bindParam(':user_agent', $this->user_agent);
        $stmt->bindParam(':devicetype', $this->devicetype);
        $stmt->bindParam(':country', $this->country);
        $stmt->bindParam(':event_type', $this->event_type);
        $stmt->bindParam(':endpoint', $this->endpoint);
        $stmt->bindParam(':method', $this->method);
        $stmt->bindParam(':status_code', $this->status_code);
        $stmt->bindParam(':is_success', $this->is_success);
        $stmt->bindParam(':failed_reason', $this->failed_reason);
        $stmt->bindParam(':created_at', $this->created_at);
        $stmt->bindParam(':last_seen_at', $this->last_seen_at);
        $stmt->execute();
        echo "Fingerprint data inserted successfully.";
    }

    
}

$test = new loginTest();
$test->setfingerprint();

