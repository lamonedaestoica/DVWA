<?php
/*

Only the admin user is allowed to access this page.

Hiding the menu link is not access control: the page has to check the caller
itself, because the URL is guessable and can simply be requested.

*/

if (dvwaCurrentUser() != "admin") {
	print "Unauthorised";
	http_response_code(403);
	exit;
}
?>
