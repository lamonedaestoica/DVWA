<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	// A session id has to be unpredictable: a counter, a timestamp or the hash of
	// either is guessable from one observed value
	$cookie_value = bin2hex(random_bytes(20));
	setcookie("dvwaSession", $cookie_value);
}
?>
