<?php

/*
 * (c) 2018 Dennis Birkholz <dennis@birkholz.org>
 *
 * $Id$
 * Author:    $Format:%an <%ae>, %ai$
 * Committer: $Format:%cn <%ce>, %ci$
 */

namespace Iqb\Ecryptfs;

/**
 * @author Dennis Birkholz <dennis@birkholz.org>
 */
class CryptoContext
{
    /**
     * @var CryptoEngineInterface
     */
    private $cryptoEngine;

    /**
     * @var string
     */
    private $fekek;

    /**
     * @var FileHeader
     */
    private $header;

    /**
     * Root initialization vector calculated from the FEK
     * @var string
     */
    private $rootIv;


    public function __construct(CryptoEngineInterface $cryptoEngine, string $fekek, FileHeader $fileHeader)
    {
        $this->cryptoEngine = $cryptoEngine;
        $this->fekek = $fekek;
        $this->header = $fileHeader;
    }


    /**
     * Create a crypto context from an open stream resource.
     * The header is read from the stream and the stream will be positioned at the beginning of the encrypted content.
     *
     * @param $streamResource
     * @param string $fekek
     * @param CryptoEngineInterface|null $cryptoEngine
     * @return CryptoContext
     */
    public static function createFromStream($streamResource, string $fekek, CryptoEngineInterface $cryptoEngine = null)
    {
        $cryptoEngine || $cryptoEngine = new OpenSslCryptoEngine();
        return new self($cryptoEngine, $fekek, FileHeader::parse($streamResource, $cryptoEngine, $fekek));
    }


    /**
     * Create a new crypto context for a new file with the supplied size.
     *
     * @param int $size
     * @param string $fekek
     * @param CryptoEngineInterface|null $cryptoEngine
     * @return CryptoContext
     */
    public static function createForSize(int $size, string $fekek, CryptoEngineInterface $cryptoEngine = null)
    {
        $cryptoEngine || $cryptoEngine = new OpenSslCryptoEngine();
        return new self($cryptoEngine, $fekek, new FileHeader($size));
    }


    /**
     * Return the encrypted binary representation of the file header
     *
     * @return string
     */
    public function encryptHeader() : string
    {
        return $this->header->generate($this->cryptoEngine, $this->fekek);
    }


    /**
     * Encrypt a single block.
     * If $blockData has fewer bytes than the block size, it is assumed to be the last block and null-padded.
     *
     * @param int $blockNumber
     * @param string $blockData
     * @return string
     */
    public function encryptBlock(int $blockNumber, string $blockData) : string
    {
        if (\strlen($blockData) > $this->header->extentSize) {
            throw new \InvalidArgumentException("Can only encrypt one block at a time!");
        }

        elseif (\strlen($blockData) < $this->header->extentSize) {
            $blockData = \str_pad($blockData, $this->header->extentSize, "\0", \STR_PAD_RIGHT);
        }

        $iv = $this->getBlockInitializationVector($blockNumber);
        return $this->cryptoEngine->encrypt($blockData, $this->header->cipherCode, $this->header->fek, $iv);
    }


    /**
     * Decrypt a single block.
     *
     * @param int $blockNumber
     * @param string $encryptedBlockData
     * @return string
     */
    public function decryptBlock(int $blockNumber, string $encryptedBlockData) : string
    {
        if (\strlen($encryptedBlockData) !== $this->header->extentSize) {
            throw new \InvalidArgumentException("Can only decrypt a single complete block at a time!");
        }

        $iv = $this->getBlockInitializationVector($blockNumber);
        $blockData = $this->cryptoEngine->decrypt($encryptedBlockData, $this->header->cipherCode, $this->header->fek, $iv);

        // Remove garbage from end
        if (($blockNumber+1) * $this->header->extentSize > $this->header->size) {
            return \substr($blockData, 0, $this->header->size % $this->header->extentSize);
        } else {
            return $blockData;
        }
    }


    public function getHeader() : FileHeader
    {
        return $this->header;
    }


    private function getBlockInitializationVector(int $blockNumber) : string
    {
        if (!$this->rootIv) {
            $this->rootIv = \hash('md5', $this->header->fek, true);
        }

        return \hash("md5", $this->rootIv . \str_pad("$blockNumber", 16, "\0", \STR_PAD_RIGHT), true);
    }
}
