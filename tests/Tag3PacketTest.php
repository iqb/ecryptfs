<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

use PHPUnit\Framework\TestCase;

/**
 * @author Dennis Birkholz <ecryptfs@birkholz.org>
 */
class Tag3PacketTest extends TestCase
{
    /**
     * Size in bytes for the binary key required for the default cipher
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/ecryptfs_kernel.h?h=v4.11.3#n136
     */
    const ECRYPTFS_DEFAULT_KEY_BYTES = 16;

    /**
     * Maximum length in in bytes for the binary key
     *
     * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n32
     */
    const ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES = 512;

    private $salt;
    private $key;


    public function setUp()
    {
        $this->salt = \random_bytes(ECRYPTFS_SALT_SIZE);
        $this->key  = \random_bytes(self::ECRYPTFS_DEFAULT_KEY_BYTES);
    }

    public function testGenerate()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . \chr(self::ECRYPTFS_DEFAULT_KEY_BYTES + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        $tag = new Tag3Packet($this->key, RFC2440_CIPHER_AES_256);
        $tag->salt = $this->salt;
        $this->assertEquals($packet, $tag->generate());
    }


    /**
     * @test
     */
    public function testParse()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . \chr(self::ECRYPTFS_DEFAULT_KEY_BYTES + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        $tag = Tag3Packet::parse($packet);
        $this->assertEquals(RFC2440_CIPHER_AES_256, $tag->cipherCode);
        $this->assertEquals($this->key, $tag->encryptedKey);
    }


    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage packet type marker
     */
    public function testParsePacketType()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE-1)
            . \chr(self::ECRYPTFS_DEFAULT_KEY_BYTES + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        Tag3Packet::parse($packet);
    }


    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage size too small
     */
    public function testParseMinPacketLength()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . \chr(ECRYPTFS_SALT_SIZE + 4)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        Tag3Packet::parse($packet);
    }


    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage key size too large
     */
    public function testParseMaxKeySize()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . Util::generateTagPacketLength(self::ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES + ECRYPTFS_SALT_SIZE + 6)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        Tag3Packet::parse($packet);
    }


    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Invalid version number
     */
    public function testParsePacketVersion()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . \chr(self::ECRYPTFS_DEFAULT_KEY_BYTES + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION + 1)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        Tag3Packet::parse($packet);
    }


    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Invalid cipher code
     */
    public function testParseCipherCode()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . \chr(self::ECRYPTFS_DEFAULT_KEY_BYTES + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(0xFF)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        Tag3Packet::parse($packet);
    }


    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage S2K
     */
    public function testParseString2KeySpecifier()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . \chr(self::ECRYPTFS_DEFAULT_KEY_BYTES + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER + 5)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        Tag3Packet::parse($packet);
    }


    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage MD5
     */
    public function testParseHashIdentifier()
    {
        $packet =
              \chr(Tag3Packet::PACKET_TYPE)
            . \chr(self::ECRYPTFS_DEFAULT_KEY_BYTES + ECRYPTFS_SALT_SIZE + 5)
            . \chr(Tag3Packet::PACKET_VERSION)
            . \chr(RFC2440_CIPHER_AES_256)
            . \chr(Tag3Packet::S2L_IDENTIFIER)
            . \chr(Tag3Packet::HASH_MD5_IDENTIFIER + 99)
            . $this->salt
            . \chr(Tag3Packet::HASH_DEFAULT_ITERATIONS)
            . $this->key
        ;

        Tag3Packet::parse($packet);
    }
}
