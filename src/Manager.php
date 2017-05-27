<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * This is the entry point for all EcryptFS operations.
 * All keys must be added here.
 *
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 */
class Manager
{
    /**
     * Number of bytes to use from the supplied salt.
     */
    const ECRYPTFS_SALT_SIZE = 8;
    
    /**
     * The salt used for creating the data (header) encryption key from the passphrase, unhex to use it.
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
     * Number of raw bytes used from signature hash
     */
    const ECRYPTFS_SIG_SIZE = 8;
    
    /**
     * Algorith used to generate keys from the supplied passphrase
     */
    const ECRYPTFS_KEY_DERIVATION_ALGO = "sha512";
    
    /**
     * Mapping from (hex) signature to actuall key
     */
    private $keys = [];
    
    
    /**
     * Generate a key from the supplied $salt and $passphrase and store it in the list of known keys, returning the hex encoded signature.
     * 
     * @param string $passphrase
     * @param string $salt
     * @return string Hex signature of the stored key
     */
    public function addKey(string $passphrase, string $salt) : string
    {
        $key = \hash(self::ECRYPTFS_KEY_DERIVATION_ALGO, \substr($salt, 0, self::ECRYPTFS_SALT_SIZE) . $passphrase, true);
        
        for ($i=1; $i<self::ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS; $i++) {
            $key = \hash(self::ECRYPTFS_KEY_DERIVATION_ALGO, $key, true);
        }
        
        $signature = \substr(\hash(self::ECRYPTFS_KEY_DERIVATION_ALGO, $key, false), 0, self::ECRYPTFS_SIG_SIZE*2);
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
     * Use the supplied passphrase to generate and register keys data and file name encryption keys from it.
     * 
     * @param string $passphrase
     */
    public function usePassphrase(string $passphrase)
    {
        $this->addKey($passphrase, self::ECRYPTFS_DEFAULT_SALT_FNEK);
        $this->addKey($passphrase, \hex2bin(self::ECRYPTFS_DEFAULT_SALT_HEX));
    }
}