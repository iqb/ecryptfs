<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * Base class for all tag classes, contains common helper functions
 * 
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 */
abstract class Tag
{
    /**
     * Try to read the length of a packet from the supplied data.
     * On success, increases $pos to point to the next byte after the length
     * 
     * @param string $data
     * @param int $pos
     */
    final public static function parsePacketLength(string $data, int &$pos = 0) : int
    {
        $packetSize = \ord($data[$pos]);
        if ($packetSize > 224) {
            throw new ParseException("Error parsing packet length!");
        }
        $pos++;
        
        // Read next byte from data
        if ($packetSize >= 192) {
            $packetSize = ($packetSize - 192) * 256;
            $packetSize += \ord($data[$pos++]);
        }
        
        return $packetSize;
    }
    
    /**
     * Generate the binary string representing the supplied length
     */
    final public static function generatePacketLength(int $length) : string
    {
        if ($length < 0) {
            throw new \InvalidArgumentException("Length must be an unsigned integer.");
        }
        
        if ($length > (32*256 + 255)) {
            throw new \InvalidArgumentException("Length too large.");
        }
        
        if ($length < 192) {
            return \chr($length);
        }
        
        $low = $length % 256;
        $high = \floor($length / 256);
        
        return \chr($high + 192) . \chr($low);
    }
}
