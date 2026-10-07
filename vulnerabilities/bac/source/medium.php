<?php
if (!defined('DVWA_WEB_PAGE_TO_ROOT')) {
    define('DVWA_WEB_PAGE_TO_ROOT', '../../../');
}

// Initialize variables
$html = "";
$id = 0;
$current_user_id = 0;

if (isset($_GET['action']) && isset($_GET['user_id'])) {
    // 1. Input validation
    if (!preg_match('/^\d+$/', $_GET['user_id'])) {
        $html .= "<p>Invalid user ID format. Please enter a number.</p>";
    } else {
        $id = intval($_GET['user_id']);

        // 2. Establish WHO IS ASKING from the server side only. A cookie, a query
        // parameter or a static token is supplied by the client and can be set to
        // anything, so none of them can decide what the client is allowed to see
        $query = "SELECT user_id, role FROM users WHERE user = ? LIMIT 1";
        $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query);
        if ($stmt) {
            $current_user = dvwaCurrentUser();
            mysqli_stmt_bind_param($stmt, "s", $current_user);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if ($result && mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $current_user_id = intval($row['user_id']);
                $user_role = $row['role'];
                mysqli_stmt_close($stmt);

                // 3. Does the target user exist?
                $check_query = "SELECT user_id FROM users WHERE user_id = ? LIMIT 1";
                $check_stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $check_query);
                mysqli_stmt_bind_param($check_stmt, "i", $id);
                mysqli_stmt_execute($check_stmt);
                mysqli_stmt_store_result($check_stmt);
                $user_exists = (mysqli_stmt_num_rows($check_stmt) > 0);
                mysqli_stmt_close($check_stmt);

                if (!$user_exists) {
                    $html .= "<p>No user found with ID: {$id}</p>";
                } else if ($current_user_id !== $id) {
                    // 4. Authorisation: the row asked for has to be the caller's own
                    $html .= "<p>Access denied. You can only view your own profile.</p>";
                } else {
                    // 5. Retrieval, bound and re-checked against the caller's id
                    $query = "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = ? AND user_id = ? LIMIT 1";
                    $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query);
                    mysqli_stmt_bind_param($stmt, "ii", $id, $current_user_id);
                    mysqli_stmt_execute($stmt);
                    $result = mysqli_stmt_get_result($stmt);

                    if ($result && mysqli_num_rows($result) > 0) {
                        $row = mysqli_fetch_assoc($result);

                        // 6. Output encoding
                        $html .= "
                            <div class=\"profile-info\">
                                <h3>User Profile</h3>
                                <p>User ID: " . htmlspecialchars($row['user_id'], ENT_QUOTES, 'UTF-8') . "</p>
                                <p>Name: " . htmlspecialchars($row['first_name'], ENT_QUOTES, 'UTF-8') . " " .
                                             htmlspecialchars($row['last_name'], ENT_QUOTES, 'UTF-8') . "</p>
                                <p>Avatar: " . htmlspecialchars($row['avatar'], ENT_QUOTES, 'UTF-8') . "</p>
                            </div>";
                    } else {
                        $html .= "<p>Access denied. Insufficient privileges.</p>";
                    }
                    mysqli_stmt_close($stmt);
                }

                // 7. Log the attempt, bound
                try {
                    $create_table = "CREATE TABLE IF NOT EXISTS bac_log (
                        id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                        user_id INT(6) NULL,
                        target_id INT(6) NULL,
                        ip_address VARCHAR(50) NULL,
                        action VARCHAR(50) NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )";
                    mysqli_query($GLOBALS["___mysqli_ston"], $create_table);

                    $ip = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
                    $target_id = $user_exists ? $id : 0;

                    $log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES (?, ?, ?)";
                    $log_stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $log_query);
                    mysqli_stmt_bind_param($log_stmt, "iis", $current_user_id, $target_id, $ip);
                    mysqli_stmt_execute($log_stmt);
                    mysqli_stmt_close($log_stmt);
                } catch (Exception $e) {
                    // Silently fail if logging doesn't work
                }
            } else {
                $html .= "<p>Authentication error.</p>";
                mysqli_stmt_close($stmt);
            }
        }
    }
}

// Show current user's role for context -- read from the database, not from a cookie
$html .= "<div class='info-banner'>Current Role: " . htmlspecialchars(isset($user_role) ? $user_role : 'regular_user', ENT_QUOTES, 'UTF-8') . "</div>";
?>
