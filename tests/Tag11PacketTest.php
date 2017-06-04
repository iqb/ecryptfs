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
class Tag11PacketTest extends \PHPUnit\Framework\TestCase
{
    private $contents = '1234567890';
    
    
    /**
     * @test
     */
    public function testGenerate()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        $this->assertEquals($packet, (new Tag11Packet($this->contents))->generate());
    }
    
    
    /**
     * @test
     */
    public function testParse()
    {
        $packet = "test"
            . \chr(Tag11Packet::PACKET_TYPE)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
            . "blabla"
        ;
        
        $pos = 4;
        $tag = Tag11Packet::parse($packet, $pos);
        $this->assertEquals($this->contents, $tag->contents);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Not enough data available
     */
    public function testParseFailShortPacket()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE-1)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0)
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Expected packet type marker
     */
    public function testParseFailPacketType()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE-1)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Error parsing packet length
     */
    public function testParseFailPacketLength()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(254)
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Invalid packet size, minimum packet size
     */
    public function testParseFailMinPacketLength()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(10)
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Corrupt packet
     */
    public function testParseFailCorruptPacket()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents) + 5)
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Invalid format specifier
     */
    public function testParseFailFormatSpecifier()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER-1)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME)-1)
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Expected filename length
     */
    public function testParseFailFilenameLength()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME)-1)
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage Invalid filename
     */
    public function testParseFailFilename()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . 'X' . \substr(Tag11Packet::PACKET_FILENAME, 1)
            . \chr(0).\chr(0).\chr(0).\chr(0)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
    
    
    /**
     * @test
     * @expectedException \Iqb\Ecryptfs\ParseException
     * @expectedExceptionMessage file date
     */
    public function testParseFailDate()
    {
        $packet = 
              \chr(Tag11Packet::PACKET_TYPE)
            . \chr(Tag11Packet::MIN_PACKET_LENGTH + \strlen($this->contents))
            . \chr(Tag11Packet::FORMAT_SPECIFIER)
            . \chr(\strlen(Tag11Packet::PACKET_FILENAME))
            . Tag11Packet::PACKET_FILENAME
            . \chr(0).\chr(1).\chr(2).\chr(3)
            . $this->contents
        ;
        
        Tag11Packet::parse($packet);
    }
}
