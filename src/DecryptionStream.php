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
     * @var CryptoEngineInterface
     */
    private $cryptoEngine;

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

    /**
     * @var int
     */
    public $cipherCode;


    public function __construct(CryptoEngineInterface $cryptoEngine, string $key, $fileHandle)
    {
        if (!\is_resource($fileHandle)) {
            throw new \InvalidArgumentException('Parameter $fileHandle must be an open file handle.');
        }

        $this->cryptoEngine = $cryptoEngine;
        $this->handle = $fileHandle;

        //\fseek($this->handle, 0);

        $header = \stream_get_contents($this->handle, ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE);

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
        $this->cipherCode = $tag3->cipherCode;

        $blockSize = $this->cryptoEngine::CIPHER_BLOCK_SIZES[$this->cipherCode];

        // Emulate ECB mode here ...
        $fekek = \substr($key, 0, $this->cryptoEngine::CIPHER_KEY_SIZES[$this->cipherCode]);
        $iv = \str_repeat("\0", $blockSize);
        $this->fileKey = '';
        foreach (\str_split(\hex2bin($tag3->encryptedKey), $blockSize) as $block) {
            $this->fileKey .= $this->cryptoEngine->decrypt($block, $this->cipherCode, $fekek, $iv);
        }

        $this->rootIV = \md5($this->fileKey, true);
    }


    public function read()
    {
        //\fseek($this->handle, $this->metadataSize + $this->currentOffset);

        if ($this->currentOffset >= $this->size) { return false; }

        $data = \stream_get_contents($this->handle, $this->extentSize);

        $page = ($this->currentOffset/$this->extentSize);
        $iv = \md5($this->rootIV . \str_pad("$page", 16, "\0", \STR_PAD_RIGHT), true);

        $decrypted = $this->cryptoEngine->decrypt($data, $this->cipherCode, $this->fileKey, $iv);
        $this->currentOffset += $this->extentSize;

        if ($this->currentOffset > $this->size) {
            return \substr($decrypted, 0, $this->size % $this->extentSize);
        } else {
            return $decrypted;
        }
    }
}
