<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Only allow include.php or file{1..3}.php -- blacklisting "../" or the http
// scheme can always be bypassed (nested traversal, URL encoding, other wrappers),
// so the page name is matched against the list of pages that actually exist
$configFileNames = [
    'include.php',
    'file1.php',
    'file2.php',
    'file3.php',
    'file4.php',
];

if( !in_array($file, $configFileNames) ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

?>
