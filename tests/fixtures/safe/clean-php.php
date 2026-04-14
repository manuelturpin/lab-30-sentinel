<?php
// SAFE: Properly secured PHP patterns
// These should NOT trigger detection patterns

// SAFE: Using filter_var instead of raw superglobals
$user_id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($user_id === false) {
    http_response_code(400);
    exit('Invalid ID');
}

// SAFE: Prepared statements instead of concatenation
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$user_id]);
$result = $stmt->fetchAll();

// SAFE: htmlspecialchars for output
$name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');
echo "<p>Welcome, {$name}</p>";

// SAFE: JSON decode instead of unserialize
$data = json_decode($_POST['data'], true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    exit('Invalid JSON');
}

// SAFE: Allowlist for file inclusion
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $allowed_pages, true)) {
    require_once("pages/{$page}.php");
}

// SAFE: Session with regeneration
session_start();
session_regenerate_id(true);
$_SESSION['user'] = $validated_username;

// SAFE: CSRF token validation
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    http_response_code(403);
    exit('CSRF validation failed');
}
?>
