<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

// Verify mbstring function overload is disabled
if (\extension_loaded('mbstring') && ((\ini_get('mbstring.func_overload') & 2) !== 0)) {
    throw new \RuntimeException('The multibyte string extensions is set to overload strlen/substr function (via mbstring.func_overload configuration in your PHP.ini). Please disable it!');
}

require_once(__DIR__ . '/constants.php');

// Register ecryptfs:// stream handler
\stream_wrapper_register(StreamWrapper::STREAM_NAME, StreamWrapper::class);
