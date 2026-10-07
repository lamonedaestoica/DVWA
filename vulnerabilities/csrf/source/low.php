<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Check Anti-CSRF token -- a password change must prove it came from a form
	// this site handed out, which a cross-site request cannot read
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Get input
	$pass_new  = $_GET[ 'password_new' ];
	$pass_conf = $_GET[ 'password_conf' ];

	// Do the passwords match?
	if( $pass_new == $pass_conf ) {
		// They do!
		$pass_new = stripslashes( $pass_new );
		$pass_new = md5( $pass_new );

		// Update the database
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$current_user = dvwaCurrentUser();
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with passwords matching
		$html .= "<pre>Passwords did not match.</pre>";
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
