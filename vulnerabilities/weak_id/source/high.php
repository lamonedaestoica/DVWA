<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	// A session id has to be unpredictable: a counter, a timestamp or the hash of
	// either is guessable from one observed value. HttpOnly keeps script from
	// reading it; Secure is left off because the lab is served over plain HTTP
	$cookie_value = bin2hex(random_bytes(20));
	setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, true);
}

?>
