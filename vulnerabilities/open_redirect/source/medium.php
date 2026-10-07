<?php

// Is the target on this site? It must carry no scheme ("http:", "javascript:")
// and no host -- including the scheme-relative "//host" form and the "/\host"
// form that browsers normalise to "//host" -- and no control characters that
// could split the Location header
function is_same_site_target ($target) {
	if (preg_match ('/[\\x00-\\x1f\\x7f\\\\]/', $target)) {
		return false;
	}
	if (strpos ($target, '//') === 0) {
		return false;
	}
	$parts = parse_url ($target);
	if ($parts === false || isset ($parts['scheme']) || isset ($parts['host'])) {
		return false;
	}
	return true;
}

if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
	if (is_same_site_target ($_GET['redirect'])) {
		header ("location: " . $_GET['redirect']);
		exit;
	} else {
		http_response_code (400);
		?>
		<p>Redirects are only allowed to pages on this site.</p>
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
