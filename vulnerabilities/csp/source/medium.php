<?php

// A nonce only works if it is unpredictable and fresh on every response: a constant
// one is simply a password that is printed on the page next to the lock. And
// 'unsafe-inline' cancels the policy outright, so it is gone
$nonce = base64_encode( random_bytes( 16 ) );
$headerCSP = "Content-Security-Policy: script-src 'self' 'nonce-" . $nonce . "';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include'])) {
$page[ 'body' ] .= "
	" . htmlspecialchars( $_POST['include'], ENT_QUOTES, 'UTF-8' ) . "
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>Whatever you enter here gets dropped directly into the page, see if you can get an alert box to pop up.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
