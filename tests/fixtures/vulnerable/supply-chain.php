<?php
// INTENTIONALLY VULNERABLE — Sentinel rule-tester fixtures
// DO NOT use in production. Every pattern here is a known vulnerability.
// CWE-502, CWE-94, CWE-22

// CWE-502: Unsafe unserialize from user input
$data = unserialize($_POST['data']);
echo $data->name;

// CWE-22: Path traversal via user input
$file = $_GET['file'];
include('/templates/' . $file);

// CWE-20: Direct use of superglobals without filtering
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysqli_query($conn, $query);

// CWE-502: Session handling
$_SESSION['prefs'] = $_POST['preferences'];
session_start();

// CWE-22: File inclusion
$page = $_GET['page'];
require_once($page . '.php');

// Access superglobals directly without sanitization
$cookie_val = $_COOKIE['session_token'];
$server_val = $_SERVER['HTTP_REFERER'];
echo $server_val;

// Session without regeneration
session_start();
$_SESSION['user'] = $_POST['username'];
$_SESSION['role'] = $_GET['role'];
?>
