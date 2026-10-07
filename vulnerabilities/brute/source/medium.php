<?php

// Credentials are only accepted in a POST body. In a query string they end up in
// server logs, browser history and Referer headers -- and a guess becomes a URL
// that any script can fire without ever loading the form.
if( isset( $_POST[ 'Login' ] ) && isset( $_POST[ 'username' ] ) && isset( $_POST[ 'password' ] ) ) {
	// Check Anti-CSRF token. A fresh one comes with every form, so each guess has
	// to load the page again; it is compared in constant time
	$token_ok = isset( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ] )
		&& is_string( $_REQUEST[ 'user_token' ] )
		&& hash_equals( $_SESSION[ 'session_token' ], $_REQUEST[ 'user_token' ] );

	if( !$token_ok ) {
		$html .= "<pre><br />CSRF token is incorrect.</pre>";
	}
	else {
		// Sanitise username input
		$user = stripslashes( $_POST[ 'username' ] );

		// Sanitise password input
		$pass = md5( stripslashes( $_POST[ 'password' ] ) );

		// Default values
		$total_failed_login = 3;
		$lockout_time       = 1;
		$account_locked     = false;

		// Check the database (Check user information). The count of failed logins
		// is what actually has to be enforced -- a sleep() only slows a guesser down
		$data = $db->prepare( 'SELECT failed_login, last_login FROM users WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
		$row = $data->fetch();

		// Check to see if the user has been locked out.
		if( ( $data->rowCount() == 1 ) && ( $row[ 'failed_login' ] >= $total_failed_login ) )  {
			// Calculate when the user would be allowed to login again
			$last_login = strtotime( $row[ 'last_login' ] );
			$timeout    = $last_login + ($lockout_time * 60);
			$timenow    = time();

			// Check to see if enough time has passed, if it hasn't locked the account
			if( $timenow < $timeout ) {
				$account_locked = true;
			}
		}

		// Check the database (if username matches the password) -- bound, so the
		// credentials can never rewrite the query into an authentication bypass
		$data = $db->prepare( 'SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR);
		$data->bindParam( ':password', $pass, PDO::PARAM_STR );
		$data->execute();
		$row = $data->fetch();

		// If its a valid login...
		if( ( $data->rowCount() == 1 ) && ( $account_locked == false ) ) {
			// Get users details
			$avatar       = $row[ 'avatar' ];
			$failed_login = $row[ 'failed_login' ];
			$last_login   = $row[ 'last_login' ];

			// Login successful
			$html .= "<p>Welcome to the password protected area " . htmlspecialchars( $user ) . "</p>";
			$html .= "<img src=\"" . htmlspecialchars( $avatar ) . "\" />";

			// Had the account been locked out since last login?
			if( $failed_login >= $total_failed_login ) {
				$html .= "<p><em>Warning</em>: Someone might of been brute forcing your account.</p>";
				$html .= "<p>Number of login attempts: <em>{$failed_login}</em>.<br />Last login attempt was at: <em>{$last_login}</em>.</p>";
			}

			// Reset bad login count
			$data = $db->prepare( 'UPDATE users SET failed_login = "0" WHERE user = (:user) LIMIT 1;' );
			$data->bindParam( ':user', $user, PDO::PARAM_STR );
			$data->execute();
		} else {
			// Login failed -- the same message either way, so the response cannot be
			// used to tell a valid username from an invalid one
			$html .= "<pre><br />Username and/or password incorrect.<br /><br/>Alternative, the account has been locked because of too many failed logins.<br />If this is the case, <em>please try again in {$lockout_time} minute(s)</em>.</pre>";

			// Update bad login count
			$data = $db->prepare( 'UPDATE users SET failed_login = (failed_login + 1) WHERE user = (:user) LIMIT 1;' );
			$data->bindParam( ':user', $user, PDO::PARAM_STR );
			$data->execute();
		}

		// Set the last login time
		$data = $db->prepare( 'UPDATE users SET last_login = now() WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
