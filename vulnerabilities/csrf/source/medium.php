<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Check Anti-CSRF token. A forged request gets an ordinary page that says no;
	// the token is compared in constant time and a new one is issued below
	$token_ok = isset( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ] )
		&& is_string( $_REQUEST[ 'user_token' ] )
		&& hash_equals( $_SESSION[ 'session_token' ], $_REQUEST[ 'user_token' ] );

	// The Referer is kept as an extra signal only: the header is optional and its
	// content is partly chosen by whoever builds the request
	if( !isset( $_SERVER[ 'HTTP_REFERER' ] ) || stripos( $_SERVER[ 'HTTP_REFERER' ], $_SERVER[ 'SERVER_NAME' ] ) === false ) {
		$token_ok = false;
	}

	if( !$token_ok ) {
		$html .= "<pre>CSRF token is incorrect.</pre>";
	}
	else {
		// Get input
		$pass_curr = isset( $_GET[ 'password_current' ] ) ? $_GET[ 'password_current' ] : '';
		$pass_new  = $_GET[ 'password_new' ];
		$pass_conf = $_GET[ 'password_conf' ];

		// Check that the current password is correct. The token proves the request
		// came from this site's form; the current password proves it came from the
		// account owner, which a token readable by an XSS elsewhere cannot
		$pass_curr = md5( stripslashes( $pass_curr ) );
		$current_user = dvwaCurrentUser();

		$data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->bindParam( ':password', $pass_curr, PDO::PARAM_STR );
		$data->execute();

		// Do both new passwords match and does the current password match the user?
		if( ( $pass_new == $pass_conf ) && ( $data->rowCount() == 1 ) ) {
			// It does!
			$pass_new = md5( stripslashes( $pass_new ) );

			// Update database with new password
			$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
			$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
			$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
			$data->execute();

			// Feedback for the user
			$html .= "<pre>Password Changed.</pre>";
		}
		else {
			// Issue with passwords matching
			$html .= "<pre>Passwords did not match or current password incorrect.</pre>";
		}
	}
}

// Generate Anti-CSRF token -- a fresh one on every page, so a harvested one is
// already stale by the time it is replayed
generateSessionToken();

?>
