<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * Symmetric-Key Encrypted Session-Key Packet (Tag 3)
 *
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 * @see https://tools.ietf.org/html/rfc2440#section-5.3
 */
class Tag3Packet
{
    const PACKET_TYPE = 0x8C;
    
    /**
     * @var int
     */
    public $packetSize;
    
    /**
     * @var int
     */
    public $encryptedKeySize;
    
    /**
     * @var int
     */
    public $version = 0x04;
    
    /**
     * @var int
     */
    public $cipherCode = 0;
    
    /**
     * @var int
     */
    public $stringToKeySpecifier = 0x03;
    
    /**
     * @var int
     */
    public $hashIdentifier = 0;
    
    /**
     * Salt as a hex string
     * @var string
     */
    public $salt;
    
    /**
     * @var int
     */
    public $hashIterations = 0;
    
    /**
     * Encrypted key as hex string
     * @var string
     */
    public $encryptedKey;
    
    
    /**
     * Try to parse a Tag3 packet from the supplied data string.
     * If the parsing was successfully, $pos will be incremented to point after the parsed data.
     */
    public static function parse(Manager $manager, string $data, int &$pos = 0) : self
    {
        $cur = $pos;
        $tag = new self();
        
        if (\ord($data[$cur]) !== self::PACKET_TYPE) {
            throw new \DomainException("Expected packet type marker 0x" . \dechex(self::PACKET_TYPE) . " but found 0x" . \bin2hex($data[$cur]));
        }
        $cur++;
        
        $tag->packetSize = Tag::parsePacketLength($data, $cur);
        if ($tag->packetSize < ECRYPTFS_SALT_SIZE + 5) {
            throw new \DomainException('Body size too small');
        }
        
        $tag->encryptedKeySize = $tag->packetSize - ECRYPTFS_SALT_SIZE - 5;
        if ($tag->encryptedKeySize > ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES) {
            throw new \DomainException('Expected key size too large');
        }
        
        $tag->version = \ord($data[$cur++]);
        if ($tag->version !== 0x04) {
            throw new \DomainException('Invalid version number 0x' . \dechex($tag->version));
        }
        
        $tag->cipherCode = \ord($data[$cur++]);
        if (!isset(RFC2440_CIPHER_CODE_TO_STRING_MAPPING[$tag->cipherCode])) {
            throw new \DomainException('Invalid cipher code 0x' . \dechex($tag->cipherCode));
        }
        
        $tag->stringToKeySpecifier = \ord($data[$cur++]);
        if ($tag->stringToKeySpecifier !== 0x03) {
            throw new \DomainException('Only S2K ID 3 is currently supported');
        }
        
        $tag->hashIdentifier = \ord($data[$cur++]);
        if ($tag->hashIdentifier !== 0x01) {
            throw new \DomainException('Only MD5 as hashing algorithm supported here');
        }
        
        $tag->salt = \bin2hex(\substr($data, $cur, ECRYPTFS_SALT_SIZE));
        $cur += ECRYPTFS_SALT_SIZE;
        
        /* This conversion was taken straight from RFC2440 */
	$tag->hashIterations = (16 + (\ord($data[$cur]) & 15)) << ((\ord($data[$cur]) >> 4) + 6);
        $cur++;
        
        $tag->encryptedKey = \bin2hex(\substr($data, $cur, $tag->encryptedKeySize));
        $cur += $tag->encryptedKeySize;
        
        $pos = $cur;
        return $tag;
    }
}
