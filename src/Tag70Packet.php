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
     * Try to parse a Tag70 packet from the supplied data string.
     * If the parsing was successfully, $pos will be incremented to point after the parsed data.
     */
    public static function parse(Manager $manager, string $data, int &$pos = 0) : self
    {
        $cur = $pos;
        $tag = new self();
        
        if (\ord($data[$cur]) !== self::PACKET_TYPE) {
            throw new \DomainException("Expected packet type marker 0x" . \bin2hex(self::PACKET_TYPE) . " but found 0x" . \bin2hex(\ord($data[$cur])));
        }
        $cur++;
        
        $tag->packetSize = Tag::parsePacketLength($data, $cur);
        
        $tag->signature = \bin2hex(\substr($data, $cur, ECRYPTFS_SIG_SIZE));
        $cur += ECRYPTFS_SIG_SIZE;
        
        $tag->blockAlignedFilenameSize = $tag->packetSize - ECRYPTFS_SIG_SIZE - 1;
        
        $tag->cipherCode = \ord($data[$cur]);
        if (!isset(RFC2440_CIPHER_CODE_TO_STRING_MAPPING[$tag->cipherCode])) {
            throw new \DomainException('Invalid cipher type 0x' . \dechex($tag->cipherCode));
        }
        if ($tag->cipherCode !== RFC2440_CIPHER_AES_256) {
            throw new \DomainException("Unsupported cipher " . RFC2440_CIPHER_CODE_TO_STRING_MAPPING[$tag->cipherCode] . ", currently only AES 256 supported!");
        }
        $cur++;
        
        $tag->encryptedFilename = \substr($data, $cur, $tag->blockAlignedFilenameSize);
        $decrypted = $manager->decrypt($tag->signature, $tag->cipherCode, $tag->encryptedFilename);
        $cur += $tag->blockAlignedFilenameSize;
        list($tag->padding, $tag->decryptedFilename) = \explode("\0", $decrypted);
        
        $pos = $cur;
        return $tag;
    }
}
