<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

/**
 * FNEK-encrypted filename as dentry name (Tag 70)
 *
 * Structure according to Ecryptfs sources:
 * Octet 0: Tag 70 identifier
 * Octets 1-N1: Tag 70 packet size (includes cipher identifier
 *              and block-aligned encrypted filename size)
 * Octets N1-N2: FNEK sig (ECRYPTFS_SIG_SIZE)
 * Octet N2-N3: Cipher identifier (1 octet)
 * Octets N3-N4: Block-aligned encrypted filename
 *  - Consists of a minimum number of random numbers, a \0
 *    separator, and then the filename
 *
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n892 ecryptfs_parse_tag_70_packet
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n614 ecryptfs_write_tag_70_packet
 */
final class Tag70Packet
{
    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n146
     */
    const PACKET_TYPE = 0x46;

    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n138 ECRYPTFS_TAG_70_DIGEST
     */
    const DIGEST = 'md5';

    /**
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n164 ECRYPTFS_TAG_70_DIGEST_SIZE
     */
    const DIGEST_SIZE = 16;

    /**
     * Minimum number of "Random" bytes (= derived with DIGEST from FNEK)
     *
     * This is intended to work as an IV but ECB is used so the IV is pointless after the first block ...
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n161
     * @link https://defuse.ca/audits/ecryptfs.htm
     */
    const MIN_RANDOM_PREPEND_BYTES = 16;

    /**
     * Used cipher is stored in the packet so use something "strong" here ...
     */
    const DEFAULT_CIPHER = RFC2440_CIPHER_AES_256;

    /**
     * @var int
     */
    public $packetSize;

    /**
     * Signature of the key used to encrypt the payload
     * @var string
     */
    public $signature;

    /**
     * Total number of bytes the encrypted filename uses including padding
     * @var int
     */
    public $blockAlignedFilenameSize;

    /**
     * Numeric identifier of the used cipher, one of the RFC2440_CIPHER_* constants
     * @var int
     */
    public $cipherCode;

    /**
     * Key size in bytes
     *
     * @var int
     */
    public $cipherKeySize;

    /**
     * @var string
     */
    public $encryptedFilename;

    /**
     * @var string
     */
    public $decryptedFilename;

    /**
     * @var string
     */
    public $padding;


    /**
     * Prevent creation without proper initialization from factory methods
     */
    private function __construct()
    {
    }


    /**
     * Generate the binary representation of this packet
     */
    final public function dump() : string
    {
        return
            \chr(self::PACKET_TYPE)
            . Util::generateTagPacketLength($this->packetSize)
            . \hex2bin($this->signature)
            . \chr($this->cipherCode)
            . $this->encryptedFilename
            ;
    }


    /**
     * Decrypt the encrypted payload and extract padding and filename from it.
     *
     * A TAG70 packet does not contain the
     *
     * @param CryptoEngineInterface $cryptoEngine
     * @param string $fnek File name encryption key
     * @return string The decrypted filename
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n1051
     */
    final public function decrypt(CryptoEngineInterface $cryptoEngine, string $fnek) : string
    {
        if ($this->signature !== ($keySignature = Util::calculateSignature($fnek))) {
            throw new \InvalidArgumentException("Signature mismatch: require {$this->signature}, got $keySignature");
        }

        $blockSize = $cryptoEngine::CIPHER_BLOCK_SIZES[$this->cipherCode];
        $iv = \str_repeat("\0", $blockSize);
        $padding = self::createRandomPrefix($fnek, self::DIGEST_SIZE);

        $correctKeySize = false;
        $possibleCipherKeySizes = ($this->cipherKeySize ? [$this->cipherKeySize] : $cryptoEngine::CIPHER_KEY_SIZES[$this->cipherCode]);

        foreach ($possibleCipherKeySizes as $cipherKeySize) {
            $realKey = \substr($fnek, 0, $cipherKeySize);

            $decrypted = '';
            foreach (\str_split($this->encryptedFilename, $blockSize) as $blockNum => $block) {
                $decrypted .= $cryptoEngine->decrypt($block, $this->cipherCode, $realKey, $iv);

                // "Random" bytes do not match expected bytes, key or key size is wrong
                if ($blockNum === 0) {
                    if (\substr($decrypted, 0, self::DIGEST_SIZE) === $padding) {
                        $this->cipherKeySize = $cipherKeySize;
                        $correctKeySize = true;
                    } else {
                        continue 2;
                    }
                }
            }

            if ($correctKeySize) {
                break;
            }
        }

        if (!$correctKeySize) {
            throw new \RuntimeException("Unable to decrypt filename, filename encryption key (FNEK) invalid or invalid key length.");
        }

        list($this->padding, $this->decryptedFilename) = \explode("\0", $decrypted, 2);
        return $this->decryptedFilename;
    }


    /**
     * Generate a Tag70 packet from for the supplied plainText string.
     *
     * @param CryptoEngineInterface $cryptoEngine
     * @param string $plainText
     * @param string $fnek File name encryption key
     * @param int $cipherCode
     * @return Tag70Packet
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n614
     */
    public static function generate(CryptoEngineInterface $cryptoEngine, string $plainText, string $fnek, int $cipherCode = self::DEFAULT_CIPHER, int $cipherKeySize = null) : self
    {
        if ($cipherKeySize === null) {
            $cipherKeySize = Util::findCipherKeySize($cipherCode, \strlen($fnek));
        }

        elseif (\strlen($fnek) < $cipherKeySize) {
            throw new \InvalidArgumentException(\şprintf("Supplied key has only %u bytes but %u bytes required for encryption.", \strlen($$fnek), $cipherKeySize));
        }

        elseif (!\in_array($cipherKeySize, CryptoEngineInterface::CIPHER_KEY_SIZES[$cipherCode])) {
            throw new \InvalidArgumentException(\şprintf("Requested key size %u bytes is unsupported for cipher 0x%x.", $cipherKeySize, $cipherCode));
        }

        $tag = new self();
        $tag->cipherCode = $cipherCode;
        $tag->signature = Util::calculateSignature($fnek);
        $tag->decryptedFilename = $plainText;

        $blockSize = $cryptoEngine::CIPHER_BLOCK_SIZES[$cipherCode];

        // Calculate length of the encoded file name and required "random" prefix
        $filenameSize = \strlen($tag->decryptedFilename);
        $randomPrefixSize = self::MIN_RANDOM_PREPEND_BYTES;
        $tag->blockAlignedFilenameSize = $randomPrefixSize + 1 + $filenameSize;
        if ($tag->blockAlignedFilenameSize % $blockSize > 0) {
            $randomPrefixSize += $blockSize - ($tag->blockAlignedFilenameSize % $blockSize);
            $tag->blockAlignedFilenameSize = $randomPrefixSize + 1 + $filenameSize;
        }
        $tag->packetSize = ECRYPTFS_SIG_SIZE + 1 + $tag->blockAlignedFilenameSize;

        // The actual padded filename contains the prefix separated by \0 from the plain text filename
        $tag->padding = self::createRandomPrefix($fnek, $randomPrefixSize);
        $paddedFilename = $tag->padding . "\0" . $tag->decryptedFilename;

        $realKey = \substr($fnek, 0, $cipherKeySize);
        $tag->encryptedFilename = '';
        $iv = \str_repeat("\0", $blockSize);
        foreach (\str_split($paddedFilename, $blockSize) as $block) {
            $tag->encryptedFilename .= $cryptoEngine->encrypt($block, $tag->cipherCode, $realKey, $iv);
        }

        return $tag;
    }


    /**
     * Generate the "random" prefix prepended to the filename before encryption.
     *
     * The "random" prefix is not that random, it is created from the MD5 sum of the FNEK
     * The prefix is a substring of md5($fnek).md5(md5($fnek)).
     *
     * @param string $fnek
     * @param int $requiredBytes
     * @return string
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n786
     */
    private static function createRandomPrefix(string $fnek, int $requiredBytes) : string
    {
        $prefix = '';
        $hash = $fnek;

        for ($i=0; $i<\ceil($requiredBytes / self::DIGEST_SIZE); $i++) {
            $hash = \hash(self::DIGEST, $hash, true);
            $prefix .= $hash;
        }

        return \substr($prefix, 0, $requiredBytes);
    }


    /**
     * Try to parse a Tag70 packet from the supplied data string.
     * Call decrypt() afterwards to actually decrypt the filename
     * If the parsing was successfully, $pos will be incremented to point after the parsed data.
     *
     * @param string $data
     * @param int $pos
     * @return Tag70Packet
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n892
     */
    public static function parse(string $data, int &$pos = 0) : self
    {
        $cur = $pos;
        $tag = new self();

        if (\ord($data[$cur]) !== self::PACKET_TYPE) {
            throw new \DomainException("Expected packet type marker 0x" . \bin2hex(self::PACKET_TYPE) . " but found 0x" . \bin2hex(\ord($data[$cur])));
        }
        $cur++;

        $tag->packetSize = Util::parseTagPacketLength($data, $cur);

        $tag->signature = \bin2hex(\substr($data, $cur, ECRYPTFS_SIG_SIZE));
        $cur += ECRYPTFS_SIG_SIZE;

        $tag->cipherCode = \ord($data[$cur]);
        if (!\array_key_exists($tag->cipherCode, CryptoEngineInterface::CIPHER_BLOCK_SIZES)) {
            throw new \DomainException('Invalid cipher type 0x' . \dechex($tag->cipherCode));
        }
        $cur++;

        $tag->blockAlignedFilenameSize = $tag->packetSize - ECRYPTFS_SIG_SIZE - 1;
        $tag->encryptedFilename = \substr($data, $cur, $tag->blockAlignedFilenameSize);
        $cur += $tag->blockAlignedFilenameSize;

        $pos = $cur;
        return $tag;
    }
}
