<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Only allow the pages that exist in this directory. Stripping "../" or matching
// "file*" can always be bypassed ("....//" collapses back to "../", and "file://"
// satisfies "file*"), so the requested name is matched against the actual list
$configFileNames = [
    'include.php',
    'file1.php',
    'file2.php',
    'file3.php',
    'file4.php',
];

if( !in_array($file, $configFileNames, true) ) {
    // This isn't the page we want! Fall back to the default page and say so,
    // rather than ending the response half-rendered
    dvwaMessagePush( "ERROR: File not found!" );
    $file = 'include.php';
}

?>
