<?php

// A repeating-key XOR is not encryption: the key length shows up in the output,
// and anything known about the plaintext recovers the key a byte at a time. This
// uses an authenticated cipher instead, with a random IV per message, so the same
// text never encodes to the same string twice and an edited message is rejected.
define ("CRYPTO_ALGO", "aes-256-gcm");

function seal ($cleartext, $key) {
    $iv  = openssl_random_pseudo_bytes (12);
    $tag = "";
    $e = openssl_encrypt ($cleartext, CRYPTO_ALGO, hash ("sha256", $key, true), OPENSSL_RAW_DATA, $iv, $tag);
    if ($e === false) {
        throw new Exception ("Encryption failed");
    }
    return $iv . $tag . $e;
}

function unseal ($ciphertext, $key) {
    if (strlen ($ciphertext) < 28) {
        throw new Exception ("Decryption failed");
    }
    $e = openssl_decrypt (substr ($ciphertext, 28), CRYPTO_ALGO, hash ("sha256", $key, true),
                          OPENSSL_RAW_DATA, substr ($ciphertext, 0, 12), substr ($ciphertext, 12, 16));
    if ($e === false) {
        throw new Exception ("Decryption failed");
    }
    return $e;
}

$key = "wachtwoord";

$errors = "";
$success = "";
$messages = "";
$encoded = null;
$encode_radio_selected = " checked='checked' ";
$decode_radio_selected = " ";
$message = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (array_key_exists ('message', $_POST)) {
			$message = $_POST['message'];
			if (array_key_exists ('direction', $_POST) && $_POST['direction'] == "decode") {
				$encoded = unseal (base64_decode ($message), $key);
				$encode_radio_selected = " ";
				$decode_radio_selected = " checked='checked' ";
			} else {
				$encoded = base64_encode(seal ($message, $key));
			}
		}
		if (array_key_exists ('password', $_POST)) {
			$password = $_POST['password'];
			// Constant-time comparison, so the response time does not leak how much
			// of the secret was guessed correctly
			if (hash_equals (hash ("sha256", "Olifant"), hash ("sha256", $password))) {
				$success = "Welcome back user";
			} else {
				$errors = "Login Failed";
			}
		}
	} catch(Exception $e) {
		$errors = $e->getMessage();
	}
}

$html = "
		<p>
		This super secure system will allow you to exchange messages with your friends without anyone else being able to read them. Use the box below to encode and decode messages.
		</p>
		<form name=\"xor\" method='post' action=\"" . $_SERVER['PHP_SELF'] . "\">
			<p>
				<label for='message'>Message:</lable><br />
				<textarea style='width: 600px; height: 56px' id='message' name='message'>" . htmlentities ($message) . "</textarea>
			</p>
			<p>
				<input type='radio' value='encode' name='direction' id='direction_encode' " . $encode_radio_selected . "><label for='direction_encode'>Encode</label> or 
				<input type='radio' value='decode' name='direction' id='direction_decode' " . $decode_radio_selected . "><label for='direction_decode'>Decode</label>
			</p>
			<p>
				<input type=\"submit\" value=\"Submit\">
			</p>
		</form>
";

if (!is_null ($encoded)) {
	$html .= "
			<p>
				<label for='encoded'>Message:</lable><br />
				<textarea readonly='readonly' style='width: 600px; height: 56px' id='encoded' name='encoded'>" . htmlentities ($encoded) . "</textarea>
			</p>";
}

$html .= "
		<hr>
		<p>
		You have intercepted the following message, decode it and log in below.
		</p>
		<p>
		<textarea readonly='readonly' style='width: 600px; height: 28px' id='encoded' name='encoded'>Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY=</textarea>
		</p>
";

if ($errors != "") {
	$html .= '<div class="warning">' . $errors . '</div>';
}

if ($messages != "") {
	$html .= '<div class="nearly">' . $messages . '</div>';
}

if ($success != "") {
	$html .= '<div class="success">' . $success . '</div>';
}

$html .= "
		<form name=\"ecb\" method='post' action=\"" . $_SERVER['PHP_SELF'] . "\">
			<p>
				<label for='password'>Password:</lable><br />
<input type='password' id='password' name='password'>
			</p>
			<p>
				<input type=\"submit\" value=\"Login\">
			</p>
		</form>
";
?>
