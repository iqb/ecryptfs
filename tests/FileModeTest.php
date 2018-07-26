<?php

/*
 * (c) 2018 Dennis Birkholz <dennis@birkholz.org>
 *
 * $Id$
 * Author:    $Format:%an <%ae>, %ai$
 * Committer: $Format:%cn <%ce>, %ci$
 */

namespace Iqb\Ecryptfs;


class FileModeTest extends \PHPUnit_Framework_TestCase
{
    private $appendixes = [
        '' => [
            'closeOnExit' => false,
            'binary' => false,
            'text' => false,
        ],
        'e' => [
            'closeOnExit' => true,
            'binary' => false,
            'text' => false,
        ],
        'b' => [
            'closeOnExit' => false,
            'binary' => true,
            'text' => false,
        ],
        'eb' => [
            'closeOnExit' => true,
            'binary' => true,
            'text' => false,
        ],
        't' => [
            'closeOnExit' => false,
            'binary' => false,
            'text' => true,
        ],
        'et' => [
            'closeOnExit' => true,
            'binary' => false,
            'text' => true,
        ],
    ];

    public function testModeR()
    {
        $mode = 'r';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertTrue($fileMode->read);
            $this->assertFalse($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertFalse($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeRPlus()
    {
        $mode = 'r+';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertTrue($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertFalse($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeW()
    {
        $mode = 'w';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertFalse($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertTrue($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeWPlus()
    {
        $mode = 'w+';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertTrue($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertTrue($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeA()
    {
        $mode = 'a';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertFalse($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertFalse($fileMode->first);
            $this->assertTrue($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertTrue($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeAPlus()
    {
        $mode = 'a+';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertTrue($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertFalse($fileMode->first);
            $this->assertTrue($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertTrue($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeX()
    {
        $mode = 'x';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertFalse($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertTrue($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeXPlus()
    {
        $mode = 'x+';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertTrue($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertTrue($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeC()
    {
        $mode = 'c';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertFalse($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }

    public function testModeCPlus()
    {
        $mode = 'c+';

        foreach ($this->appendixes as $appendix => $flags) {
            $fileMode = new FileMode($mode . $appendix);
            $this->assertTrue($fileMode->read);
            $this->assertTrue($fileMode->write);
            $this->assertTrue($fileMode->first);
            $this->assertFalse($fileMode->last);
            $this->assertFalse($fileMode->truncate);
            $this->assertFalse($fileMode->append);
            $this->assertTrue($fileMode->create);
            $this->assertFalse($fileMode->exclusive);
            $this->assertSame($flags['closeOnExit'], $fileMode->closeOnExec, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['binary'], $fileMode->binary, 'Mode: ' . $mode . $appendix);
            $this->assertSame($flags['text'], $fileMode->text, 'Mode: ' . $mode . $appendix);
            $this->assertSame($mode . $appendix, $fileMode->toMode());
        }
    }
}
