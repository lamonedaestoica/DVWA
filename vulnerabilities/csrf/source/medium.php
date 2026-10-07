<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Check Anti-CSRF token -- the Referer check below is kept as defence in
	// depth, but it is not a control on its own: the header is optional and an
	// attacker's page can get it to contain the server name
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Checks to see where the request came from
	if( isset( $_SERVER[ 'HTTP_REFERER' ] ) && stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
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
	else {
		// Didn't come from a trusted source
		$html .= "<pre>That request didn't look correct.</pre>";
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
