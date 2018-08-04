<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * Class to convert binary data to/from base256 to base64 with filename save alphabet.
 * Used to create encrypted filenames.
 *
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 */
final class BaseConverter
{
    const PORTABLE_FILENAME_CHARS = '-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    const FILENAME_REVERSE_MAPPING = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 7 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 15 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 23 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 31 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 39 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 47 */
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, /* 55 */
        0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 63 */
        0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, /* 71 */
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, /* 79 */
        0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, /* 87 */
        0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, /* 95 */
        0x00, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, /* 103 */
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, /* 111 */
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, /* 119 */
        0x3D, 0x3E, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, /* 123 - 255 initialized to 0x00 */
    ];


    /**
     * Decode the base64 encoded string into a base256 binary string
     *
     * @param string $encoded
     * @return string
     */
    public static function decode(string $encoded) : string
    {
        $srcSize = \strlen($encoded);
        $currentBitOffset = 0;
        $dstByteOffset = 0;
        $dst = [];

        for ($srcByteOffset=0; $srcByteOffset<$srcSize; $srcByteOffset++) {
            $byte = self::FILENAME_REVERSE_MAPPING[\ord($encoded[$srcByteOffset])];

            switch ($currentBitOffset) {
                case 0:
                    $dst[$dstByteOffset] = ($byte << 2);
                    $currentBitOffset = 6;
                    break;
                case 6:
                    $dst[$dstByteOffset++] |= ($byte >> 4);
                    $dst[$dstByteOffset] = (($byte & 0xF) << 4);
                    $currentBitOffset = 4;
                    break;
                case 4:
                    $dst[$dstByteOffset++] |= ($byte >> 2);
                    $dst[$dstByteOffset] = ($byte << 6);
                    $currentBitOffset = 2;
                    break;
                case 2:
                    $dst[$dstByteOffset++] |= ($byte);
                    $currentBitOffset = 0;
                    break;
            }
        }

        return \implode('', \array_map('\\chr', $dst));
    }

    /**
     * Encode a (base256) binary string into a base64 string (using the filename save alphabet)
     *
     * @param string $decoded
     * @return string
     */
    public static function encode(string $decoded) : string
    {
        $inputLength = \strlen($decoded);

        // Each encoded char holds only 6 bit of the original 8 bit
        // so a block of 3 original chars results in 4 encoded chars.
        // Pad the input with \0-bytes so string can be split in 3 char blocks.
        if (($inputLength % 3) > 0) {
            $padding = (3 - ($inputLength % 3));
            $decoded .= \str_repeat("\0", $padding);
            $inputLength += $padding;
        }

        $encoded = '';
        for ($i=0; $i<$inputLength; $i+=3) {
            $code1 = (\ord($decoded[$i]) >> 2) & 0x3F;
            $code2 = ((\ord($decoded[$i]) << 4) & 0x30) | ((\ord($decoded[$i+1]) >> 4) & 0x0F);
            $code3 = ((\ord($decoded[$i+1]) << 2) & 0x3C) | ((\ord($decoded[$i+2]) >> 6) & 0x03);
            $code4 = \ord($decoded[$i+2]) & 0x3F;

            $encoded .= self::PORTABLE_FILENAME_CHARS[$code1];
            $encoded .= self::PORTABLE_FILENAME_CHARS[$code2];
            $encoded .= self::PORTABLE_FILENAME_CHARS[$code3];
            $encoded .= self::PORTABLE_FILENAME_CHARS[$code4];
        }

        return $encoded;
    }
}
