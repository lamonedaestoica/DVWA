<?php

// Only scripts served by this origin. The previous policy trusted a list of public
// CDNs and paste sites -- anyone can upload the script that the policy then trusts,
// so an allowlist of third parties is not a boundary at all
$headerCSP = "Content-Security-Policy: script-src 'self';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include'])) {
	$include = $_POST['include'];

	// The value becomes a <script src>, so accepting any URL means running any
	// script. Only a path on this site is written into the page -- the policy
	// above is the second line of defence, not the only one
	if (is_string ($include) && preg_match ('#^/(?![/\\\\])[A-Za-z0-9._~/%-]*$#', $include)) {
		$page[ 'body' ] .= "
	<script src='" . htmlspecialchars( $include, ENT_QUOTES, 'UTF-8' ) . "'></script>
";
	} else {
		$page[ 'body' ] .= "
	<p>Only scripts hosted on this site can be included.</p>
";
	}
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>You can include scripts from external sources, examine the Content Security Policy and enter a URL to include here:</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
<p>
	You will probably need to do some reading up on what some of the domains allowed by the CSP do and how they can be used.
</p>
';
