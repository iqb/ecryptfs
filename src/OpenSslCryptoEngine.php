<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

final class OpenSslCryptoEngine implements CryptoEngineInterface
{
    const CIPHER_MAPPING = [
        RFC2440_CIPHER_AES_128 => "AES-128-CBC",
        RFC2440_CIPHER_AES_192 => "AES-192-CBC",
        RFC2440_CIPHER_AES_256 => "AES-256-CBC",
    ];

    /**
     * Encrypt the supplied data using the specified cipher algorithm.
     *
     * @param string $data The plain text data to encrypt, length must be a multiple of the block size of the cipher
     * @param int $cipherCode One of the RFC2440_CIPHER_* constants specifying the cipher
     * @param string $key Raw binary key, must match the required key length of the cipher
     * @param string $iv Initialization vector
     * @return string
     */
    final public function encrypt(string $data, int $cipherCode, string $key, string $iv): string
    {
        \assert(isset(self::CIPHER_MAPPING[$cipherCode]), "Cipher 0x" . \dechex($cipherCode) . " not implemented!");
        \assert(\strlen($key) === self::CIPHER_KEY_SIZES[$cipherCode], "Invalid key size specified.");

        $cipher = self::CIPHER_MAPPING[$cipherCode];

        if (false === ($encrypted = \openssl_encrypt($data, $cipher, $key, \OPENSSL_RAW_DATA|\OPENSSL_NO_PADDING, $iv))) {
            throw new \RuntimeException("Encryption failed with error: " . \openssl_error_string());
        }

        \assert(($openSslError = \openssl_error_string() !== ''), "OpenSSL error message: $openSslError");

        return $encrypted;
    }

    /**
     * @param string $data Encrypted data to decrypt, length must be a multiple of the block size of the cipher
     * @param int $cipherCode One of the RFC2440_CIPHER_* constants specifying the cipher
     * @param string $key Raw binary key, must match the required key length of the cipher
     * @param string $iv Initialization vector
     * @return string
     */
    final public function decrypt(string $data, int $cipherCode, string $key, string $iv): string
    {
        \assert(isset(self::CIPHER_MAPPING[$cipherCode]), "Cipher 0x" . \dechex($cipherCode) . " not implemented!");
        \assert(\strlen($key) === self::CIPHER_KEY_SIZES[$cipherCode], "Invalid key size specified.");

        $cipher = self::CIPHER_MAPPING[$cipherCode];

        if (false === ($decrypted = \openssl_decrypt($data, $cipher, $key, \OPENSSL_RAW_DATA|\OPENSSL_NO_PADDING, $iv))) {
            throw new \RuntimeException("Decryption failed with error: " . \openssl_error_string());
        }

        \assert(($openSslError = \openssl_error_string()) !== '', "OpenSSL error message: $openSslError");

        return $decrypted;
    }
}
