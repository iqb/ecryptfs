<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

class StreamWrapper
{
    /**
     * Name of the registered stream and name of the array key in the context options
     */
    const STREAM_NAME = 'ecryptfs';

    /**
     * Name of the passphrase context option
     */
    const CONTEXT_PASSPHRASE = 'passphrase';

    /**
     * Name of the engine context option
     */
    const CONTEXT_ENGINE = 'engine';

    /**
     * Name of the stream context option
     */
    const CONTEXT_STREAM = 'stream';


    /**
     * @var resource
     */
    public $context;

    /**
     * The stream to the encrypted data
     *
     * @var resource
     */
    private $encrypted;

    /**
     * @var CryptoEngineInterface
     */
    private $cryptoEngine;

    /**
     * @var FileHeader
     */
    private $header;

    /**
     * Total number of blocks according to header
     *
     * @var int
     */
    private $blocks;

    /**
     * Current block
     *
     * @var int
     */
    private $block;

    /**
     * Maximum stream position reachable
     *
     * @var int
     */
    private $maxPosition;

    /**
     * Absolute position in the stream
     *
     * @var int
     */
    private $position;


    public function stream_open(string $path, string $mode, int $options, string &$opened_path = null) : bool
    {
        $context = \stream_context_get_options($this->context);
        $myContext = (isset($context[self::STREAM_NAME]) && \is_array($context[self::STREAM_NAME]) ? $context[self::STREAM_NAME] : []);

        // Read passphrase from context and derive file encryption key encryption key (FEKEK)
        if (\array_key_exists(self::CONTEXT_PASSPHRASE, $myContext)) {
            $this->fekek = Util::deriveFEKEK($myContext[self::CONTEXT_PASSPHRASE]);
        } else {
            if ($options & \STREAM_REPORT_ERRORS) {
                throw new \InvalidArgumentException("Passphrase required!");
            }
            return false;
        }

        // Get crypto engine from context or use OpenSSL by default
        if (\array_key_exists(self::CONTEXT_ENGINE, $myContext)) {
            $this->cryptoEngine = $myContext[self::CONTEXT_ENGINE];
            if (!$this->cryptoEngine instanceof CryptoEngineInterface) {
                if ($options & \STREAM_REPORT_ERRORS) {
                    new \InvalidArgumentException("Supplied crypto engine must implement " . CryptoEngineInterface::class);
                }
                return false;
            }
        } else {
            $this->cryptoEngine = new OpenSslCryptoEngine();
        }

        // Use stream from context or open file
        if (\array_key_exists(self::CONTEXT_STREAM, $myContext)) {
            $this->encrypted = $myContext[self::CONTEXT_STREAM];
        }

        else {
            $prefix = self::STREAM_NAME . '://';

            if (\substr($path, 0, \strlen($prefix)) !== $prefix) {
                if ($options & \STREAM_REPORT_ERRORS) {
                    \trigger_error("Invalid path!", \E_USER_WARNING);
                }
                return false;
            }

            $realPath = \substr($path, \strlen($prefix));
            if ($options & \STREAM_REPORT_ERRORS) {
                $this->encrypted = \fopen($realPath, $mode, ($options & \STREAM_USE_PATH), $this->context);
            } else {
                $this->encrypted = @\fopen($realPath, $mode, ($options & \STREAM_USE_PATH), $this->context);
            }
        }

        if (!\is_resource($this->encrypted)) {
            if ($options & \STREAM_REPORT_ERRORS) {
                \trigger_error("Failed to open encrypted file!", \E_USER_WARNING);
            }
            return false;
        }

        $this->header = FileHeader::parse($this->encrypted);
        $this->header->decryptFileKey($this->cryptoEngine, $this->fekek);
        $this->position = $this->header->metadataSize;
        $this->maxPosition = $this->header->metadataSize + $this->header->size;

        return true;
    }


    /**
     * @param int $length
     * @return string
     * @link http://php.net/manual/en/streamwrapper.stream-read.php
     */
    public function stream_read(int $length) : string
    {
        if (($length % $this->header->extentSize) !== 0) {
            throw new \InvalidArgumentException("Can only read multiples of " . $this->header->extentSize . " blocks");
        }

        $readBlocks = $length / $this->header->extentSize;
        $startBlock = \floor(($this->position - $this->header->metadataSize) / $this->header->extentSize);

        $return = '';
        for ($i=0; $i<$readBlocks && !$this->stream_eof(); $i++) {
            $block = $startBlock + $i;
            $iv = \hash("md5", $this->header->rootIv . \str_pad("$block", 16, "\0", \STR_PAD_RIGHT), true);

            $encrypted = \stream_get_contents($this->encrypted, $this->header->extentSize);
            if (\strlen($encrypted) !== $this->header->extentSize) {
                throw new \RuntimeException("Could not read enough data from stream, got only " . \strlen($encrypted) . " bytes instead of " . $this->header->extentSize);
            }
            $this->position = \ftell($this->encrypted);
            $decrypted = $this->cryptoEngine->decrypt($encrypted, $this->header->cipherCode, $this->header->fileKey, $iv);

            // Remove garbage from end
            if ($this->position > $this->maxPosition) {
                $return .= \substr($decrypted, 0, $this->header->size % $this->header->extentSize);
            } else {
                $return .= $decrypted;
            }
        }

        return $return;
    }


    public function stream_eof() : bool
    {
        return ($this->position >= $this->maxPosition);
    }


    final public function stream_stat() : array
    {
        return [
            'size' => $this->header->size,
            'blksize' => $this->header->extentSize,
            'blocks' => \ceil($this->header->size / $this->header->extentSize),
        ];
    }
}
