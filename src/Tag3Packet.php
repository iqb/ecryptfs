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
 * @link https://tools.ietf.org/html/rfc2440#section-5.3 OpenPGP Message Format: Symmetric-Key Encrypted Session-Key Packets (Tag 3)
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n1360 parse_tag_3_packet
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n2184 write_tag_3_packet
 */
class Tag3Packet
{
    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n140
     */
    const PACKET_TYPE = 0x8C;

    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n1455
     */
    const PACKET_VERSION = 0x04;

    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n1478
     */
    const S2L_IDENTIFIER = 0x03;

    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n1485
     */
    const HASH_MD5_IDENTIFIER = 0x01;

    /**
     * 65536 iterations
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n2392
     */
    const HASH_DEFAULT_ITERATIONS = 0x60;


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


    public function __construct(string $encryptedKey, int $cipherType = ECRYPTFS_DEFAULT_CIPHER)
    {
        $this->encryptedKey = $encryptedKey;
        $this->cipherCode = $cipherType;
    }


    public function generate() : string
    {
        return
              \chr(Tag3Packet::PACKET_TYPE)
            . Util::generateTagPacketLength(\strlen($this->encryptedKey) + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr($this->cipherCode)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . ($this->salt ?: \random_bytes(ECRYPTFS_SALT_SIZE))
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->encryptedKey
        ;
    }


    /**
     * Try to parse a Tag3 packet from the supplied data string.
     * If the parsing was successfully, $pos will be incremented to point after the parsed data.
     *
     * Only encryptedKey and cipherCode are used, all other fields are not used.
     */
    public static function parse(string $data, int &$pos = 0) : self
    {
        $cur = $pos;

        if (\ord($data[$cur]) !== self::PACKET_TYPE) {
            throw new ParseException("Expected packet type marker 0x" . \dechex(self::PACKET_TYPE) . " but found 0x" . \bin2hex($data[$cur]));
        }
        $cur++;

        $packetSize = Util::parseTagPacketLength($data, $cur);
        if ($packetSize < ECRYPTFS_SALT_SIZE + 5) {
            throw new ParseException('Body size too small');
        }

        $encryptedKeySize = $packetSize - ECRYPTFS_SALT_SIZE - 5;
        if ($encryptedKeySize > ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES) {
            throw new ParseException('Expected key size too large');
        }

        $version = \ord($data[$cur++]);
        if ($version !== self::PACKET_VERSION) {
            throw new ParseException('Invalid version number 0x' . \dechex($version));
        }

        $cipherCode = \ord($data[$cur++]);
        if (!\array_key_exists($cipherCode, RFC2440_CIPHER_CODE_TO_STRING_MAPPING)) {
            throw new ParseException('Invalid cipher code 0x' . \dechex($cipherCode));
        }

        $stringToKeySpecifier = \ord($data[$cur++]);
        if ($stringToKeySpecifier !== self::S2L_IDENTIFIER) {
            throw new ParseException('Only S2K ID 3 is currently supported');
        }

        $hashIdentifier = \ord($data[$cur++]);
        if ($hashIdentifier !== self::HASH_MD5_IDENTIFIER) {
            throw new ParseException('Only MD5 as hashing algorithm supported here');
        }

        $salt = \substr($data, $cur, ECRYPTFS_SALT_SIZE);
        $cur += ECRYPTFS_SALT_SIZE;

        /* This conversion was taken straight from RFC2440 */
	    $hashIterations = (16 + (\ord($data[$cur]) & 15)) << ((\ord($data[$cur]) >> 4) + 6);
        $cur++;

        $encryptedKey = \substr($data, $cur, $encryptedKeySize);
        $cur += $encryptedKeySize;

        $tag = new self($encryptedKey, $cipherCode);
        $tag->salt = $salt;
        $tag->hashIdentifier = $hashIdentifier;
        $tag->hashIterations = $hashIterations;

        $pos = $cur;
        return $tag;
    }
}
