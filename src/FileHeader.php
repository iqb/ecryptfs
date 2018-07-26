<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * The FileHeader class represents the metadata stored at the beginning of each encrypted file.
 * It marks the file as a valid EcryptFS encrypted file (via the Magic Marker) and
 * contains information about the real file size of the encrypted file, the key to decrypt the file,
 * the method used for encrypting the file, etc.
 */
class FileHeader
{
    /**
     * Default file header size
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n45
     */
    const MINIMUM_HEADER_EXTENT_SIZE = 8192;

    /**
     * Default block size
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n44
     */
    const DEFAULT_EXTENT_SIZE = 4096;

    /**
     * Magic marker to detect if a file is a valid EcryptFS file
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n130
     */
    const MAGIC_MARKER = 0x3c81b7f5;

    /**
     * Current version written into encrypted files
     */
    const DEFAULT_VERSION = 3;

    /**
     * Size of the unencrypted file
     *
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
     * @var int
     */
    public $cipherCode;

    /**
     * Encrypted file encryption key (FEK), encrypted with the FEKEK
     *
     * @var string
     */
    public $encryptedFileKey;

    /**
     * Decrypted file encryption key (FEK)
     *
     * @var string
     */
    public $fileKey;

    /**
     * Root initialisation vector, used to calculate IV for each block.
     *
     * @var string
     */
    public $rootIv;

    /**
     * The marker that is used together with MAGIC_MARKER to indicate a valid header
     *
     * @var int
     */
    public $marker;


    public function __construct(int $size, int $cipherCode, string $fek, int $version = self::DEFAULT_VERSION, int $flags = 10, int $extentSize = self::DEFAULT_EXTENT_SIZE, int $extentsAtFront = 2)
    {
        $this->size = $size;
        $this->cipherCode = $cipherCode;
        $this->fileKey = $fek;
        $this->version = $version;
        $this->flags = $flags;
        $this->extentSize = $extentSize;
        $this->extentsAtFront = $extentsAtFront;
        $this->metadataSize = $this->extentsAtFront * $this->extentSize;
        $this->rootIv = \hash('md5', $this->fileKey, true);
    }


    public static function parse($fileHandle, CryptoEngineInterface $cryptoEngine, string $fekek) : self
    {
        if (!\is_resource($fileHandle)) {
            throw new \InvalidArgumentException('Parameter $fileHandle must be an open file handle.');
        }

        $headerData = \stream_get_contents($fileHandle, self::MINIMUM_HEADER_EXTENT_SIZE);
        if (\strlen($headerData) < self::MINIMUM_HEADER_EXTENT_SIZE) {
            throw new \RuntimeException('Could not read enough data to parse header.');
        }

        $headerValues = unpack('Jsize/N2marker/Cversion/sreserved/Cflags/Nextentsize/nextentsatfront', $headerData);
        $pos = 26;

        // see https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/crypto.c?h=v4.11.3#n857
        if (($headerValues['marker1'] ^ self::MAGIC_MARKER) !== $headerValues['marker2']) {
            throw new \DomainException('Invalid magic marker.');
        }

        $tag3 = Tag3Packet::parse($headerData, $pos);
        $fekekSignature = Util::calculateSignature($fekek, true);
        $tag11 = Tag11Packet::parse($headerData, $pos);

        if ($tag11->contents !== $fekekSignature) {
            throw new \InvalidArgumentException(\sprintf('Provided FEKEK has signature 0x%s but require key with signature 0x%s!', \bin2hex($fekekSignature), \bin2hex($tag11->contents)));
        }
        $fek = self::decryptFileKey($cryptoEngine, $tag3->cipherCode, $fekek, $tag3->encryptedKey);

        $header = new self(
            $headerValues['size'],
            $tag3->cipherCode,
            $fek,
            $headerValues['version'],
            $headerValues['flags'],
            $headerValues['extentsize'],
            $headerValues['extentsatfront']
        );
        $header->encryptedFileKey = $tag3->encryptedKey;
        $header->marker = $headerValues['marker1'];

        // Read remaining header data so stream is positioned at the beginning of the data
        if ($header->metadataSize > self::MINIMUM_HEADER_EXTENT_SIZE) {
            $headerData .= \stream_get_contents($fileHandle, ($header->metadataSize - self::MINIMUM_HEADER_EXTENT_SIZE));
        }

        return $header;
    }


    /**
     * Decrypt the file encryption key (FEK) using the file encryption key encryption key (FEKEK).
     * The cipher method for FEK encryption and for file contents encryption is encoded in the header.
     *
     * @param CryptoEngineInterface $cryptoEngine
     * @param int $cipherCode The cipher code used to encrypt the FEK
     * @param string $fekek The FEKEK
     * @param string $encryptedFek The encrypted FEK
     * @return string The decrypted FEK
     */
    private static function decryptFileKey(CryptoEngineInterface $cryptoEngine, int $cipherCode, string $fekek, string $encryptedFek) : string
    {
        if (\in_array(\strlen($encryptedFek), $cryptoEngine::CIPHER_KEY_SIZES[$cipherCode], true)) {
            $cipherKeySize = \strlen($encryptedFek);
        } else {
            throw new \InvalidArgumentException(\sprintf("Invalid key size (%u byte) for cipher 0x%x detected, %s bytes possible. File header may be corrupt!", \strlen($encryptedFek), $cipherCode, \implode(', ', $cryptoEngine::CIPHER_KEY_SIZES[$cipherCode])));
        }

        if (\strlen($fekek) < $cipherKeySize) {
            throw new \InvalidArgumentException(\sprintf("Decryption requires %u key bytes, supplied FEKEK has only %u bytes!", $cipherKeySize, \strlen($fekek)));
        }
        $realFekek = \substr($fekek, 0, $cipherKeySize);

        $blockSize = $cryptoEngine::CIPHER_BLOCK_SIZES[$cipherCode];
        $iv = \str_repeat("\0", $blockSize);

        // Emulate ECB mode here ...
        $fek = '';
        foreach (\str_split($encryptedFek, $blockSize) as $block) {
            $fek .= $cryptoEngine->decrypt($block, $cipherCode, $realFekek, $iv);
        }

        return $fek;
    }
}
