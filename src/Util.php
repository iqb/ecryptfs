<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

abstract class Util
{
    /**
     * Derive a key from the supplied passphrase and salt
     *
     * @param string $passPhrase
     * @param string $salt
     * @param bool $hexEncode Whether to return the key hex encoded or not
     * @return string
     */
    final public static function deriveKey(string $passPhrase, string $salt, bool $hexEncode = false) : string
    {
        $key = \hash(ECRYPTFS_KEY_DERIVATION_ALGO, \substr($salt, 0, ECRYPTFS_SALT_SIZE) . $passPhrase, true);

        for ($i=1; $i<ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS; $i++) {
            $key = \hash(ECRYPTFS_KEY_DERIVATION_ALGO, $key, true);
        }

        return ($hexEncode ? \bin2hex($key) : $key);
    }

    /**
     * Derive the file encryption key encrytion key (FEKEK) from the supplied passphrase.
     *
     * @param string $passPhrase
     * @param bool $hexEncode Whether to return the key hex encoded or not
     * @return string Derived key
     */
    final public static function deriveFEKEK(string $passPhrase, bool $hexEncode = false) : string
    {
        return self::deriveKey($passPhrase, \hex2bin(ECRYPTFS_DEFAULT_SALT_HEX), $hexEncode);
    }

    /**
     * Derive the file encryption key encrytion key (FEKEK) from the supplied passphrase.
     *
     * @param string $passPhrase
     * @param bool $hexEncode Whether to return the key hex encoded or not
     * @return string Derived key
     */
    final public static function deriveFNEK(string $passPhrase, bool $hexEncode = false) : string
    {
        // Due to a programming error in the original Ecryptfs source code
        // the value of the ECRYPTFS_DEFAULT_SALT_FNEK_HEX is not hex decoded
        // but truncated and used without conversion.
        return self::deriveKey($passPhrase, \substr(ECRYPTFS_DEFAULT_SALT_FNEK_HEX, 0, 8), $hexEncode);
    }

    /**
     * Calculate the signature of a key
     *
     * @param string $key Raw binary blob
     * @return string Hex encoded signature
     */
    final public static function calculateSignature(string $key) : string
    {
        return \bin2hex(\substr(\hash(ECRYPTFS_KEY_DERIVATION_ALGO, $key, true), 0, ECRYPTFS_SIG_SIZE));
    }


    /**
     * Try to read the length of a packet from the supplied data.
     * On success, increases $pos to point to the next byte after the length
     *
     * @param string $data
     * @param int $pos
     * @return int
     */
    final public static function parseTagPacketLength(string $data, int &$pos = 0) : int
    {
        $packetSize = \ord($data[$pos]);
        if ($packetSize > 224) {
            throw new \InvalidArgumentException("Error parsing packet length!");
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
     *
     * @param int $length
     * @return string
     */
    final public static function generateTagPacketLength(int $length) : string
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


    /**
     * Check whether the supplied filename is encrypted
     *
     * @param string $filename
     * @return bool
     */
    public static function isEncryptedFilename(string $filename) : bool
    {
        return (\substr(\basename($filename), 0, \strlen(ECRYPTFS_PREFIX)) === ECRYPTFS_PREFIX);
    }


    /**
     * Encrypt the supplied filename
     *
     * @param string $filename
     * @return string
     */
    public static function encryptFilename(CryptoEngineInterface $cryptoEngine, string $filename, string $key, int $cipherCode = Tag70Packet::DEFAULT_CIPHER) : string
    {
        $tag = Tag70Packet::generate($cryptoEngine, $filename, $key, $cipherCode);
        return ECRYPTFS_PREFIX . BaseConverter::encode($tag->dump());
    }


    /**
     * Decrypt the supplied filename
     */
    public static function decryptFilename(CryptoEngineInterface $cryptoEngine, string $filename, string $key) : string
    {
        if (!self::isEncryptedFilename($filename)) {
            return $filename;
        }

        $dirname = \dirname($filename);
        $decoded = BaseConverter::decode(\substr(\basename($filename), \strlen(ECRYPTFS_PREFIX)));
        $tag = Tag70Packet::parse($decoded);
        $tag->decrypt($cryptoEngine, $key);

        return ($dirname && $dirname != '.' ? $dirname . '/' : '') . $tag->decryptedFilename;
    }
}
