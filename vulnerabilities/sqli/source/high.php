<?php

if( isset( $_SESSION [ 'id' ] ) ) {
	// Get input
	$id = $_SESSION[ 'id' ];

	// Was a number entered? The session is attacker-controlled through
	// session-input.php, so it is validated and bound like any other input
	if( is_numeric( $id ) ) {
		$id = intval( $id );

		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				// Check the database
				$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
				$data->bindParam( ':id', $id, PDO::PARAM_INT );
				$data->execute();

				// Get results
				while( $row = $data->fetch() ) {
					// Get values
					$first = $row[ 'first_name' ];
					$last  = $row[ 'last_name' ];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
				break;
			case SQLITE:
				global $sqlite_db_connection;

				$stmt = $sqlite_db_connection->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;' );
				$stmt->bindValue( ':id', $id, SQLITE3_INTEGER );
				try {
					$results = $stmt->execute();
				} catch (Exception $e) {
					echo 'Caught exception: ' . $e->getMessage();
					exit();
				}

				if ($results) {
					while ($row = $results->fetchArray()) {
						// Get values
						$first = $row["first_name"];
						$last  = $row["last_name"];

						// Feedback for end user
						$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
					}
				}
				break;
		}
	}
}

?>
