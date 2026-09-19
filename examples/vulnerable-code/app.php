<?php
// INTENTIONALLY VULNERABLE sample — for demonstrating ClayScan's SAST.

// command injection
system("ls " . $_GET['dir']);

// SQL injection with superglobal
$result = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $_POST['name'] . "'");

// local/remote file inclusion
include($_GET['page'] . ".php");

// reflected XSS
echo "Welcome " . $_GET['user'];

// object injection
$obj = unserialize($_COOKIE['session']);
?>
