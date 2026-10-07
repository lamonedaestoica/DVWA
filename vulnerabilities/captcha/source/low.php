<?php

if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {
	// Hide the CAPTCHA form
	$hide_form = true;

	// Get input
	$pass_new  = $_POST[ 'password_new' ];
	$pass_conf = $_POST[ 'password_conf' ];

	// Check CAPTCHA from 3rd party
	$resp = recaptcha_check_answer(
		$_DVWA[ 'recaptcha_private_key'],
		$_POST['g-recaptcha-response']
	);

	// Did the CAPTCHA fail?
	if( !$resp ) {
		// What happens when the CAPTCHA was entered incorrectly
		$html     .= "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>";
		$hide_form = false;
		unset( $_SESSION[ 'captcha_passed' ] );
		return;
	}
	else {
		// CAPTCHA was correct. Do both new passwords match?
		if( $pass_new == $pass_conf ) {
			// Remember server side that this session cleared the CAPTCHA. A hidden
			// form field cannot carry this: the client writes it, so it proves nothing
			$_SESSION[ 'captcha_passed' ] = true;

			// Show next stage for the user
			$html .= "
				<pre><br />You passed the CAPTCHA! Click the button to confirm your changes.<br /></pre>
				<form action=\"#\" method=\"POST\">
					<input type=\"hidden\" name=\"step\" value=\"2\" />
					<input type=\"hidden\" name=\"password_new\" value=\"" . htmlspecialchars( $pass_new, ENT_QUOTES, 'UTF-8' ) . "\" />
					<input type=\"hidden\" name=\"password_conf\" value=\"" . htmlspecialchars( $pass_conf, ENT_QUOTES, 'UTF-8' ) . "\" />
					<input type=\"submit\" name=\"Change\" value=\"Change\" />
				</form>";
		}
		else {
			// Both new passwords do not match.
			$html     .= "<pre>Both passwords must match.</pre>";
			$hide_form = false;
			unset( $_SESSION[ 'captcha_passed' ] );
		}
	}
}

if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '2' ) ) {
	// Hide the CAPTCHA form
	$hide_form = true;

	// Step 1 is not optional: jumping straight here, or posting a forged
	// "passed_captcha" field, must not be enough
	if( empty( $_SESSION[ 'captcha_passed' ] ) ) {
		$html     .= "<pre><br />You have not passed the CAPTCHA.</pre>";
		$hide_form = false;
		return;
	}

	// One shot -- a cleared CAPTCHA cannot be replayed for a second change
	unset( $_SESSION[ 'captcha_passed' ] );

	// Get input
	$pass_new  = $_POST[ 'password_new' ];
	$pass_conf = $_POST[ 'password_conf' ];

	// Check to see if both password match
	if( $pass_new == $pass_conf ) {
		// They do!
		$pass_new = stripslashes( $pass_new );
		$pass_new = md5( $pass_new );

		// Update database
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$current_user = dvwaCurrentUser();
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the end user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with the passwords matching
		$html .= "<pre>Passwords did not match.</pre>";
		$hide_form = false;
	}
}

?>
