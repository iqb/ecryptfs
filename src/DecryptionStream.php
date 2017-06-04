<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 */
class DecryptionStream
{
    /**
     * @var Manager
     */
    private $manager;
    
    /**
     * The open file resource for the encrypted file
     * @var resource
     */
    private $handle;
    
    /**
     * @var int
     */
    private $currentOffset = 0;
    
    /**
     * Unencrypted file size
     * @var int
     */
    public $size;
    
    /**
     * @var int
     */
    public $version;
    
    /**
     * @var int
     */
    public $flags;
    
    /**
     * @var int
     */
    public $extentSize;
    
    /**
     * @var int
     */
    public $extentsAtFront;
    
    /**
     * @var int
     */
    public $metadataSize;
    
    /**
     *
     * @var string
     */
    public $fileKey;
    
    /**
     * @var string
     */
    public $rootIV;
    
    
    public function __construct(Manager $manager, $fileHandle)
    {
        if (!\is_resource($fileHandle)) {
            throw new \InvalidArgumentException('Parameter $fileHandle must be an open file handle.');
        }
        
        $this->manager = $manager;
        $this->handle = $fileHandle;
        
        \fseek($this->handle, 0);
        
        $header = '';
        do {
            $header .= \fread($this->handle, ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE - \strlen($header));
        } while (!feof($this->handle) && (\strlen($header) < ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE));
        
        if (\strlen($header) < ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE) {
            throw new \DomainException('Could not read enough data to parse header.');
        }
        
        $headerValues = unpack('Jsize/N2marker/Cversion/sreserved/Cflags/Nextentsize/nextentsatfront', $header);
        $pos = 26;
        
        if (($headerValues['marker1'] ^ ECRYPTFS_MAGIC_MARKER) !== $headerValues['marker2']) {
            throw new \DomainException('Invalid magic marker.');
        }
        
        $this->size = $headerValues['size'];
        $this->version = $headerValues['version'];
        $this->flags = $headerValues['flags'];
        $this->extentSize = $headerValues['extentsize'];
        $this->extentsAtFront = $headerValues['extentsatfront'];
        $this->metadataSize = $this->extentsAtFront * $this->extentSize;
        
        $tag3 = Tag3Packet::parse($header, $pos);
        
        $this->fileKey = $manager->decrypt($manager->getDefaultFEKEK(), $tag3->cipherCode, \hex2bin($tag3->encryptedKey));
        $this->rootIV = \md5($this->fileKey, true);
    }
    
    
    public function read()
    {
        \fseek($this->handle, $this->metadataSize + $this->currentOffset);
        
        if ($this->currentOffset >= $this->size) { return false; }
        
        $tryBytes = ($this->currentOffset + $this->extentSize > $this->size ? $this->size - $this->currentOffset : $this->extentSize);
        
        $data = '';
        do {
            $data = \fread($this->handle, $this->extentSize - \strlen($data));
        } while (!\feof($this->handle) && \strlen($data) < $this->extentSize);
        
        $page = ($this->currentOffset/$this->extentSize);
        $iv = \md5($this->rootIV . \str_pad("$page", 16, "\0", \STR_PAD_RIGHT), true);
        $decrypted = $this->manager->decryptWithKey($this->fileKey, RFC2440_CIPHER_AES_256, $data, $iv);
        
        $this->currentOffset += $tryBytes;
        
        if ($tryBytes < $this->extentSize) {
            return \substr($decrypted, 0, $tryBytes);
        } else {
            return $decrypted;
        }
    }
}
