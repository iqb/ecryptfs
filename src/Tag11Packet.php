<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * Literal Data Packet (Tag 11)
 * 
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 * @link https://tools.ietf.org/html/rfc2440#section-5.9 OpenPGP Message Format: Literal Data Packet (Tag 11)
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n1536 parse_tag_11_packet
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n2123 write_tag_11_packet
 */
final class Tag11Packet extends Tag
{
    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n141
     */
    const PACKET_TYPE = 0xED;
    
    const MIN_PACKET_LENGTH = 14;
    
    /**
     * Binary data format specifier, see keystore.c  
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n1611
     */
    const FORMAT_SPECIFIER = 0x62;
    
    /**
     * Hardcoded filename field
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n2148
     */
    const PACKET_FILENAME = '_CONSOLE';
    
    /**
     * @var string
     */
    public $contents;
    
    
    public function __construct($contents)
    {
        $this->contents = $contents;
    }
    
    
    /**
     * Generate the binary representation of this packet
     */
    public function generate() : string
    {
        return
            \chr(self::PACKET_TYPE)
            . \chr(self::MIN_PACKET_LENGTH + \strlen($this->contents)) // FIXME: handle packet size > 191
            . \chr(self::FORMAT_SPECIFIER)
            . \chr(\strlen(self::PACKET_FILENAME))
            . self::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
    }
    
    
    /**
     * Try to parse a Tag11 packet from the supplied data string.
     * If the parsing was successfully, $pos will be incremented to point after the parsed data.
     */
    public static function parse(string $data, int &$pos = 0) : self
    {
        $cur = $pos;
        $remaining = \strlen($data) - $cur;
        
        if ($remaining < self::MIN_PACKET_LENGTH+2) {
            throw new ParseException('Not enough data available to read for minimum packet length.');
        }
        
        if (\ord($data[$cur]) !== self::PACKET_TYPE) {
            throw new ParseException("Expected packet type marker 0x" . \bin2hex(self::PACKET_TYPE) . " but found 0x" . \bin2hex(\ord($data[$cur])));
        }
        $cur++;
        
        $packetSize = parent::parsePacketLength($data, $cur);
        if ($packetSize < self::MIN_PACKET_LENGTH) {
            throw new ParseException("Invalid packet size, minimum packet size is " . self::MIN_PACKET_LENGTH . " but got " . $packetSize);
        }
        
        $remaining -= ($cur - $pos);
        if ($remaining < $packetSize) {
            throw new ParseException("Corrupt packet.");
        }
        
        if (\ord($data[$cur++]) !== self::FORMAT_SPECIFIER) {
            throw new ParseException('Invalid format specifier');
        }
        
        $filenameLength = \ord($data[$cur++]);
        if ($filenameLength !== \strlen(self::PACKET_FILENAME)) {
            throw new ParseException("Expected filename length of " . \strlen(self::PACKET_FILENAME) . " but got " . $filenameLength);
        }
        
        $filename = \substr($data, $cur, $filenameLength);
        if ($filename !== self::PACKET_FILENAME) {
            throw new ParseException('Invalid filename "' . $filename . '", expected "' . self::PACKET_FILENAME . '".');
        }
        $cur += $filenameLength;
        
        if (\substr($data, $cur, 4) !== \chr(0).\chr(0).\chr(0).\chr(0)) {
            throw new ParseException('Expected file date to be zero.');
        }
        $cur += 4;
        
        $tag = new self(\substr($data, $cur, ($packetSize - self::MIN_PACKET_LENGTH)));
        $cur += ($packetSize - self::MIN_PACKET_LENGTH);
        
        $pos = $cur;
        return $tag;
    }
}
