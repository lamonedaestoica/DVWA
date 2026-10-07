<?php

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input -- encoded on output, so the value is always rendered as text and
	// never as markup. Filtering out "<script>" only moves the payload elsewhere
	$name = htmlspecialchars( $_GET[ 'name' ] );

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";
}

?>
