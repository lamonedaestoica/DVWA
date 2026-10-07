<?php

if( isset( $_GET[ 'Submit' ] ) ) {
	// Get input
	$id = $_GET[ 'id' ];
	$exists = false;

	// Was a number entered? Anything else never reaches the database, and the
	// lookup itself is bound so the value can never rewrite the query
	if( is_numeric( $id ) ) {
		$id = intval( $id );

		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				// Check the database
				$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id);' );
				$data->bindParam( ':id', $id, PDO::PARAM_INT );
				$data->execute();

				$exists = ( $data->rowCount() > 0 );
				break;
			case SQLITE:
				global $sqlite_db_connection;

				$stmt = $sqlite_db_connection->prepare( 'SELECT COUNT(first_name) AS numrows FROM users WHERE user_id = :id;' );
				$stmt->bindValue( ':id', $id, SQLITE3_INTEGER );
				try {
					$results = $stmt->execute();
					$row = $results->fetchArray();
					$exists = ( $row !== false && $row[ 'numrows' ] > 0 );
				} catch(Exception $e) {
					$exists = false;
				}
				break;
		}
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// Same shape of answer either way: a different status code, or a delay on
		// the miss, is itself the oracle a blind injection reads
		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}
}

?>
