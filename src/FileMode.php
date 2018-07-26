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
class FileMode
{
    const READ          = 1<<0;
    const WRITE         = 1<<1;
    const FIRST         = 1<<2;
    const LAST          = 1<<3;
    const TRUNCATE      = 1<<4;
    const APPEND        = 1<<5;
    const CREATE        = 1<<6;
    const EXCLUSIVE     = 1<<7;
    const CLOSE_ON_EXEC = 1<<8;

    const MODE2FLAGS = [
        'r'  => self::READ | self::FIRST,
        'r+' => self::READ | self::WRITE | self::FIRST,
        'w'  =>              self::WRITE | self::FIRST |              self::TRUNCATE |                self::CREATE,
        'w+' => self::READ | self::WRITE | self::FIRST |              self::TRUNCATE |                self::CREATE,
        'a'  =>              self::WRITE |               self::LAST |                  self::APPEND | self::CREATE,
        'a+' => self::READ | self::WRITE |               self::LAST |                  self::APPEND | self::CREATE,
        'x'  =>              self::WRITE | self::FIRST |                                              self::CREATE | self::EXCLUSIVE,
        'x+' => self::READ | self::WRITE | self::FIRST |                                              self::CREATE | self::EXCLUSIVE,
        'c'  =>              self::WRITE | self::FIRST |                                              self::CREATE,
        'c+' => self::READ | self::WRITE | self::FIRST |                                              self::CREATE,
    ];

    const FLAGS2MODE = [
        self::READ | self::FIRST                                                                                             => 'r',
        self::READ | self::WRITE | self::FIRST                                                                               => 'r+',
                     self::WRITE | self::FIRST |              self::TRUNCATE |                self::CREATE                   => 'w',
        self::READ | self::WRITE | self::FIRST |              self::TRUNCATE |                self::CREATE                   => 'w+',
                     self::WRITE |               self::LAST |                  self::APPEND | self::CREATE                   => 'a',
        self::READ | self::WRITE |               self::LAST |                  self::APPEND | self::CREATE                   => 'a+',
                     self::WRITE | self::FIRST |                                              self::CREATE | self::EXCLUSIVE => 'x',
        self::READ | self::WRITE | self::FIRST |                                              self::CREATE | self::EXCLUSIVE => 'x+',
                     self::WRITE | self::FIRST |                                              self::CREATE                   => 'c',
        self::READ | self::WRITE | self::FIRST |                                              self::CREATE                   => 'c+',
    ];

    /**
     * File is opened for reading
     * @var bool
     */
    public $read = false;

    /**
     * File is opened for writing
     * @var bool
     */
    public $write = false;

    /**
     * File pointer is placed at the beginning
     * @var bool
     */
    public $first = false;

    /**
     * File pointer is placed at the end
     * @var bool
     */
    public $last = false;

    /**
     * Truncate the file, implies $first
     * @var bool
     */
    public $truncate = false;

    /**
     * Open file in append only mode, implies $write, seeking is only possible for the reading position
     * @var bool
     */
    public $append = false;

    /**
     * Create the file if it does not exist, implies $write
     * @var bool
     */
    public $create = false;

    /**
     * Create the file if it exists and fail if it does not exist, implies $first, $create
     * @var bool
     */
    public $exclusive = false;

    /**
     * Set close-on-exec flag on the opened file descriptor. Only available in PHP compiled on POSIX.1-2008 conform systems.
     * @var bool
     */
    public $closeOnExec = false;

    /**
     * Stream is a binary stream, no newline conversion is performed
     * @var bool
     */
    public $binary = false;

    /**
     * Stream is a text stream, newline conversion is performed (windows only)
     * @var bool
     */
    public $text = false;


    public function __construct(string $mode = null)
    {
        if ($mode !== null) {
            if (!\preg_match('/^(?<mode>[acrwx]\+?)(?<closeonexec>e)?(?<translation>[bt])?$/', $mode, $matches)) {
                throw new \InvalidArgumentException('Can not parse supplied mode!');
            }

            if (!\array_key_exists($matches['mode'], self::MODE2FLAGS)) {
                throw new \InvalidArgumentException('Invalid mode supplied');
            }

            $flags = self::MODE2FLAGS[$matches['mode']];
            $this->read      = (($flags & self::READ)      !== 0);
            $this->write     = (($flags & self::WRITE)     !== 0);
            $this->first     = (($flags & self::FIRST)     !== 0);
            $this->last      = (($flags & self::LAST)      !== 0);
            $this->truncate  = (($flags & self::TRUNCATE)  !== 0);
            $this->append    = (($flags & self::APPEND)    !== 0);
            $this->create    = (($flags & self::CREATE)    !== 0);
            $this->exclusive = (($flags & self::EXCLUSIVE) !== 0);

            $this->closeOnExec = (\array_key_exists('closeonexec', $matches) && $matches['closeonexec'] === 'e');
            $this->binary      = (\array_key_exists('translation', $matches) && $matches['translation'] === 'b');
            $this->text        = (\array_key_exists('translation', $matches) && $matches['translation'] === 't');
        }
    }


    /**
     * Create a string usable in fopen() from the set flags
     * @return string
     */
    public function toMode() : string
    {
        // Implications:
        $this->first = $this->first || $this->truncate || $this->exclusive;
        $this->create = $this->create || $this->exclusive;
        $this->write = $this->write || $this->append || $this->create;

        if (!$this->read && !$this->write) {
            throw new \InvalidArgumentException('File must be open in read, write or readwrite mode!');
        }

        if ($this->last && $this->truncate) {
            throw new \InvalidArgumentException('Truncating and seeking to the last position is not possible!');
        }

        if ($this->binary && $this->text) {
            throw new \InvalidArgumentException("Text and binary flags are mutually exclusive!");
        }

        $flags = 0;
        $flags |= ($this->read      ? self::READ      : 0);
        $flags |= ($this->write     ? self::WRITE     : 0);
        $flags |= ($this->first     ? self::FIRST     : 0);
        $flags |= ($this->last      ? self::LAST      : 0);
        $flags |= ($this->truncate  ? self::TRUNCATE  : 0);
        $flags |= ($this->append    ? self::APPEND    : 0);
        $flags |= ($this->create    ? self::CREATE    : 0);
        $flags |= ($this->exclusive ? self::EXCLUSIVE : 0);

        if (!\array_key_exists($flags, self::FLAGS2MODE)) {
            throw new \InvalidArgumentException("The flag combination provided is invalid!");
        }
        $mode = self::FLAGS2MODE[$flags];
        $mode .= ($this->closeOnExec ? 'e' : '');
        $mode .= ($this->binary      ? 'b' : '');
        $mode .= ($this->text        ? 't' : '');

        return $mode;
    }
}
