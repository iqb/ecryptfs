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
     * The salt used for creating the file encryption key encryption key from the passphrase, unhex to use it.
     *
     * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/include/ecryptfs.h#L75
     * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/utils/ecryptfs_add_passphrase.c#L83
     */
    const DEFAULT_SALT_HEX = "0011223344556677";

    /**
     * The salt used for creating the file name encryption key from the passphrase.
     * Due to a programming error in the original ecryptfs user space library,
     * the salt is not unhexed before use.
     *
     * As a result only the first half (99887766) is used literally.
     *
     * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/include/ecryptfs.h#L76
     * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/utils/ecryptfs_add_passphrase.c#L108
     */
    const DEFAULT_SALT_FNEK_HEX = "9988776655443322";

    /**
     * Algorith used to generate keys from the supplied passphrase
     *
     * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/libecryptfs/main.c#L220
     */
    const KEY_DERIVATION_ALGO = "sha512";

    /**
     * Number of iterations when deriving the keys from the passphrase
     *
     * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/include/ecryptfs.h#L130
     * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/libecryptfs/main.c#L223
     */
    const DEFAULT_NUM_HASH_ITERATIONS = 65536;

    /**
     * Filename prefix for encrypted file names
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n171
     */
    const FNEK_ENCRYPTED_FILENAME_PREFIX = 'ECRYPTFS_FNEK_ENCRYPTED.';

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
        $key = \hash(self::KEY_DERIVATION_ALGO, \substr($salt, 0, ECRYPTFS_SALT_SIZE) . $passPhrase, true);

        for ($i=1; $i<self::DEFAULT_NUM_HASH_ITERATIONS; $i++) {
            $key = \hash(self::KEY_DERIVATION_ALGO, $key, true);
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
        return self::deriveKey($passPhrase, \hex2bin(self::DEFAULT_SALT_HEX), $hexEncode);
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
        return self::deriveKey($passPhrase, \substr(self::DEFAULT_SALT_FNEK_HEX, 0, 8), $hexEncode);
    }

    /**
     * Calculate the signature of a key
     *
     * @param string $key Raw binary blob
     * @return string Hex encoded signature
     */
    final public static function calculateSignature(string $key) : string
    {
        return \bin2hex(\substr(\hash(self::KEY_DERIVATION_ALGO, $key, true), 0, ECRYPTFS_SIG_SIZE));
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
        return (\substr(\basename($filename), 0, \strlen(self::FNEK_ENCRYPTED_FILENAME_PREFIX )) === self::FNEK_ENCRYPTED_FILENAME_PREFIX);
    }


    /**
     * Encrypt the supplied filename
     *
     * @param CryptoEngineInterface $cryptoEngine
     * @param string $filename
     * @param string $fnek
     * @param int $cipherCode
     * @param int|null $cipherKeySize
     * @return string
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/crypto.c?h=v4.11.3#n1498
     */
    public static function encryptFilename(CryptoEngineInterface $cryptoEngine, string $filename, string $fnek, int $cipherCode = Tag70Packet::DEFAULT_CIPHER, int $cipherKeySize = null) : string
    {
        $tag = Tag70Packet::generate($cryptoEngine, $filename, $fnek, $cipherCode, $cipherKeySize);
        return self::FNEK_ENCRYPTED_FILENAME_PREFIX  . BaseConverter::encode($tag->dump());
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
        $decoded = BaseConverter::decode(\substr(\basename($filename), \strlen(self::FNEK_ENCRYPTED_FILENAME_PREFIX )));
        $tag = Tag70Packet::parse($decoded);
        $tag->decrypt($cryptoEngine, $key);

        return ($dirname && $dirname != '.' ? $dirname . '/' : '') . $tag->decryptedFilename;
    }


    /**
     * Find the largest possible cipher key size for the given cipher and key length
     *
     * @param int $cipherCode
     * @param int $keyLength
     * @return mixed
     */
    public static function findCipherKeySize(int $cipherCode, int $keyLength)
    {
        foreach (CryptoEngineInterface::CIPHER_KEY_SIZES[$cipherCode] as $possibleCipherKeySize) {
            if ($possibleCipherKeySize <= $keyLength) {
                $cipherKeySize = $possibleCipherKeySize;
                break;
            }
        }

        if (!isset($cipherKeySize)) {
            throw new \RuntimeException("Supplied key has only %u bytes, not enough for cipher 0x%x", $keyLength, $cipherCode);
        }

        return $cipherKeySize;
    }
}
