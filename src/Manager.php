<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * Filename prefix for encrypted file names
 */
const ECRYPTFS_PREFIX = 'ECRYPTFS_FNEK_ENCRYPTED.';

/**
 * Magic marker to detect if a file is a valid EcryptFS file
 */
const ECRYPTFS_MAGIC_MARKER = 0x3c81b7f5;

/**
 * Default block size
 */
const ECRYPTFS_DEFAULT_EXTENT_SIZE = 4096;

/**
 * Default file header size
 */
const ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE = 8192;
    
/**
 * Number of bytes to use from the supplied salt.
 */
const ECRYPTFS_SALT_SIZE = 8;

/**
 * The salt used for creating the file encryption key encryption key from the passphrase, unhex to use it.
 */
const ECRYPTFS_DEFAULT_SALT_HEX = "0011223344556677";

/**
 * The salt used for creating the file name encryption key from the passphrase.
 * Due to a programming error in the original ecryptfs user space library,
 * the salt is not unhexed before use. As a result only the first half is used literally.
 * 
 * See ECRYPTFS_DEFAULT_SALT_FNEK for the real salt used.
 */
const ECRYPTFS_DEFAULT_SALT_FNEK_HEX = "9988776655443322";

/**
 * The salt used for creating the file name encryption key from the passphrase.
 */
const ECRYPTFS_DEFAULT_SALT_FNEK = "99887766";

/**
 * Number of iterations when deriving the keys from the passphrase
 */
const ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS = 65536;

/**
 * Algorith used to generate keys from the supplied passphrase
 */
const ECRYPTFS_KEY_DERIVATION_ALGO = "sha512";

/**
 * Number of raw bytes used from signature hash
 */
const ECRYPTFS_SIG_SIZE = 8;

/**
 * Default (and currently only supported) cipher used for encryption
 */
const ECRYPTFS_DEFAULT_CIPHER = "aes256";

/**
 * Size in bytes for the binary key required for the default cipher
 */
const ECRYPTFS_DEFAULT_KEY_BYTES = 16;

/**
 * Maximum key length of encrypted keys
 */
const ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES = 512;

const RFC2440_CIPHER_DES3_EDE = 0x02;
const RFC2440_CIPHER_CAST_5 = 0x03;
const RFC2440_CIPHER_BLOWFISH = 0x04;
const RFC2440_CIPHER_AES_128 = 0x07;
const RFC2440_CIPHER_AES_192 = 0x08;
const RFC2440_CIPHER_AES_256 = 0x09;
const RFC2440_CIPHER_TWOFISH = 0x0a;
const RFC2440_CIPHER_CAST_6 = 0x0b;
    
const RFC2440_CIPHER_CODE_TO_STRING_MAPPING = [
    RFC2440_CIPHER_DES3_EDE => "des3_ede",
    RFC2440_CIPHER_CAST_5   => "cast5",
    RFC2440_CIPHER_BLOWFISH => "blowfish",
    RFC2440_CIPHER_AES_128  => "aes128",
    RFC2440_CIPHER_AES_192  => "aes192",
    RFC2440_CIPHER_AES_256  => "aes256",
    RFC2440_CIPHER_TWOFISH  => "twofish",
    RFC2440_CIPHER_CAST_6   => "cast6",
];


/**
 * This is the entry point for all EcryptFS operations.
 * All keys must be added here.
 *
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 */
class Manager
{
    /**
     * Mapping from (hex) signature to actual key
     */
    private $keys = [];
    
    /**
     * Signature of the default file name encryption key
     * @var string
     */
    private $defaultFNEK;
    
    /**
     * Signature of the default file encryption key encryption key
     * @var string
     */
    private $defaultFEKEK;
    
    
    /**
     * Generate a key from the supplied $salt and $passphrase and store it in the list of known keys, returning the hex encoded signature.
     * 
     * @param string $passphrase
     * @param string $salt
     * @return string Hex signature of the stored key
     */
    public function addKey(string $passphrase, string $salt) : string
    {
        $key = \hash(ECRYPTFS_KEY_DERIVATION_ALGO, \substr($salt, 0, ECRYPTFS_SALT_SIZE) . $passphrase, true);
        
        for ($i=1; $i<ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS; $i++) {
            $key = \hash(ECRYPTFS_KEY_DERIVATION_ALGO, $key, true);
        }
        
        $signature = \substr(\hash(ECRYPTFS_KEY_DERIVATION_ALGO, $key, false), 0, ECRYPTFS_SIG_SIZE*2);
        $this->keys[$signature] = \bin2hex($key);
        
        return $signature;
    }
    
    
    /**
     * Get all stored keys as a signature => key mapping
     */
    public function getKeys() : array
    {
        return $this->keys;
    }
    
    
    /**
     * Get the key for the supplied signature
     */
    public function getKey(string $signature) : string
    {
        if (!isset($this->keys[$signature])) {
            throw new \InvalidArgumentException("No key with signature $signature exists!");
        }
        
        return $this->keys[$signature];
    }
    
    
    /**
     * Get the signature of the default file name encryption key
     */
    public function getDefaultFNEK() : string
    {
        return $this->defaultFNEK;
    }
    
    
    /**
     * Get the signature of the default file encryption key encryption key
     */
    public function getDefaultFEKEK() : string
    {
        return $this->defaultFEKEK;
    }
    
    
    /**
     * Use the supplied passphrase to generate and register keys data and file name encryption keys from it.
     * 
     * @param string $passphrase
     */
    public function usePassphrase(string $passphrase)
    {
        $fnek = $this->addKey($passphrase, ECRYPTFS_DEFAULT_SALT_FNEK);
        if (!$this->defaultFNEK) {
            $this->defaultFNEK = $fnek;
        }
        
        $fekek = $this->addKey($passphrase, \hex2bin(ECRYPTFS_DEFAULT_SALT_HEX));
        if (!$this->defaultFEKEK) {
            $this->defaultFEKEK = $fekek;
        }
    }
    
    
    /**
     * Decrypt the supplied filename and return the corresponding Tag70Packet
     */
    public function getTag70PacketFromFilename(string $filename) : Tag70Packet
    {
        $filename = \basename($filename);
        
        if (\substr($filename, 0, \strlen(ECRYPTFS_PREFIX)) !== ECRYPTFS_PREFIX) {
            throw new \DomainException("Supplied filename '$filename' misses required prefix '" . ECRYPTFS_PREFIX . "'");
        }
        
        $decodedFilename = BaseConverter::decode(\substr($filename, \strlen(ECRYPTFS_PREFIX)));
        
        return Tag70Packet::parse($this, $decodedFilename);
    }
    
    
    /**
     * Decrypt the supplied filename.
     */
    public function decryptFilename(string $filename) : string
    {
        return $this->getTag70PacketFromFilename($filename)->decryptedFilename;
    }
    
    
    /**
     * Decrypt a string, select the key matching the supplied key signature.
     * 
     * @param string $keySignature The (hex encoded) signature of a key
     * @param int $cipherCode One of the RFC2440_CIPHER_* constants
     * @param string $data Raw binary string to decrypt. Length must be a multiple of the blocksize of the cipher.
     * @param string $iv Initialization vector
     */
    public function decrypt(string $keySignature, int $cipherCode, string $data, string $iv = null) : string
    {
        return $this->decryptWithKey(\hex2bin($this->getKey($keySignature)), $cipherCode, $data, $iv);
    }
    
    
    /**
     * Decrypt a string
     * 
     * @param string $key The raw binary key
     * @param int $cipherCode One of the RFC2440_CIPHER_* constants
     * @param string $data Raw binary string to decrypt. Length must be a multiple of the blocksize of the cipher.
     * @param string $iv Initialization vector
     */
    public function decryptWithKey(string $key, int $cipherCode, string $data, string $iv = null) : string
    {
        if ($cipherCode !== RFC2440_CIPHER_AES_256) {
            throw new \DomainException('Unsupported cipher code 0x' . \dechex($cipherCode));
        }
        
        if ($iv) {
            $algo = "AES-256-CBC";
        } else {
            $algo = "AES-256-ECB";
        }
        
        if (false === ($decrypted = \openssl_decrypt($data, $algo, $key, \OPENSSL_RAW_DATA|\OPENSSL_NO_PADDING, $iv))) {
            throw new \DomainException("Decryption failed with error: " . \openssl_error_string());
        }
        
        return $decrypted;
    }
}
