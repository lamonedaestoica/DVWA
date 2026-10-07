<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input -- encoded on the way in, so whatever the guestbook
	// renders later is text; the insert is bound so it cannot rewrite the query
	$message = stripslashes( $message );
	$message = htmlspecialchars( $message );

	// Sanitize name input
	$name = stripslashes( $name );
	$name = htmlspecialchars( $name );

	// Update database
	$data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
	$data->bindParam( ':message', $message, PDO::PARAM_STR );
	$data->bindParam( ':name', $name, PDO::PARAM_STR );
	$data->execute();
}

?>
