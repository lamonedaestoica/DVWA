<?php

// Only ever redirect to a target this page itself offers. Rejecting "http://" or
// requiring a substring are both bypassable -- "//evil.tld" is scheme-relative and
// carries no "http://", and "info.php" can be embedded in an absolute URL
$allowed_targets = array (
	"info.php?id=1",
	"info.php?id=2",
);

if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
	if (in_array ($_GET['redirect'], $allowed_targets, true)) {
		header ("location: " . $_GET['redirect']);
		exit;
	} else {
		http_response_code (500);
		?>
		<p>You can only redirect to the info page.</p>
		<?php
		exit;
	}
}

http_response_code (500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>
