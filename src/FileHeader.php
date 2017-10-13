<?php


namespace Iqb\Ecryptfs;


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


    public static function parse($fileHandle) : self
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

        $header = new self();
        $header->size           = $headerValues['size'];
        $header->version        = $headerValues['version'];
        $header->flags          = $headerValues['flags'];
        $header->extentSize     = $headerValues['extentsize'];
        $header->extentsAtFront = $headerValues['extentsatfront'];
        $header->metadataSize   = $header->extentsAtFront * $header->extentSize;

        // Read remaining header data so stream is positioned at the beginning of the data
        if ($header->metadataSize > self::MINIMUM_HEADER_EXTENT_SIZE) {
            $headerData .= \stream_get_contents($fileHandle, ($header->metadataSize - self::MINIMUM_HEADER_EXTENT_SIZE));
        }

        $tag3 = Tag3Packet::parse($headerData, $pos);
        $header->cipherCode = $tag3->cipherCode;
        $header->encryptedFileKey = $tag3->encryptedKey;

        return $header;
    }

    public function decryptFileKey(CryptoEngineInterface $cryptoEngine, string $fekek)
    {
        $realFekek = \substr($fekek, 0, $cryptoEngine::CIPHER_KEY_SIZES[$this->cipherCode]);
        $blockSize = $cryptoEngine::CIPHER_BLOCK_SIZES[$this->cipherCode];
        $iv = \str_repeat("\0", $blockSize);

        // Emulate ECB mode here ...
        $this->fileKey = '';
        foreach (\str_split($this->encryptedFileKey, $blockSize) as $block) {
            $this->fileKey .= $cryptoEngine->decrypt($block, $this->cipherCode, $realFekek, $iv);
        }

        $this->rootIv = \hash('md5', $this->fileKey, true);
    }
}
