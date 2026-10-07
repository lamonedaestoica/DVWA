<?php
header("Content-Type: application/json; charset=UTF-8");

// The callback name is written straight into a script body, so it is executable
// code, not data. Only the one function this endpoint exists to feed is accepted;
// anything else would let the caller choose what the page runs
$allowed_callbacks = array ("solveSum");

if (array_key_exists ("callback", $_GET) && in_array ($_GET['callback'], $allowed_callbacks, true)) {
	$callback = $_GET['callback'];
} else {
	return "";
}

$outp = array ("answer" => "15");

echo $callback . "(".json_encode($outp).")";
?>
