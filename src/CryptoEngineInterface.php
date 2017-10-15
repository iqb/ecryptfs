<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

interface CryptoEngineInterface
{
    /**
     * Block sizes of possible ciphers in byte
     */
    const CIPHER_BLOCK_SIZES = [
        RFC2440_CIPHER_DES3_EDE => 8,
        RFC2440_CIPHER_CAST_5   => 8,
        RFC2440_CIPHER_BLOWFISH => 8,
        RFC2440_CIPHER_AES_128  => 16,
        RFC2440_CIPHER_AES_192  => 16,
        RFC2440_CIPHER_AES_256  => 16,
        RFC2440_CIPHER_TWOFISH  => 16,
        RFC2440_CIPHER_CAST_6   => 16,
    ];

    /**
     * Key sizes for ciphers in byte
     *
     * @link https://tools.ietf.org/html/rfc2440#section-9.2
     * @link https://tools.ietf.org/html/rfc4880#section-9.2
     */
    const CIPHER_KEY_SIZES = [
        // Triple-DES (DES-EDE, as per spec - 168 bit key derived from 192)
        RFC2440_CIPHER_DES3_EDE => [ 24 ],
        // CAST5 (128 bit key, as per RFC 2144)
        RFC2440_CIPHER_CAST_5   => [ 16 ],
        // Blowfish (128 bit key, 16 rounds)
        RFC2440_CIPHER_BLOWFISH => [ 16 ],
        // AES with 128-bit key
        RFC2440_CIPHER_AES_128  => [ 16 ],
        // AES with 192-bit key
        RFC2440_CIPHER_AES_192  => [ 24 ],
        // AES with 256-bit key
        RFC2440_CIPHER_AES_256  => [ 32 ],
        // Twofish with 256-bit key
        RFC2440_CIPHER_TWOFISH  => [ 32, 24, 16 ],
        RFC2440_CIPHER_CAST_6   => [ 32, 28, 24, 20, 16 ],
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
    public function encrypt(string $data, int $cipherCode, string $key, string $iv) : string;

    /**
     * @param string $data Encrypted data to decrypt, length must be a multiple of the block size of the cipher
     * @param int $cipherCode One of the RFC2440_CIPHER_* constants specifying the cipher
     * @param string $key Raw binary key, must match the required key length of the cipher
     * @param string $iv Initialization vector
     * @return string
     */
    public function decrypt(string $data, int $cipherCode, string $key, string $iv) : string;
}
