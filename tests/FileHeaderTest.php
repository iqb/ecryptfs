<?php

/*
 * (c) 2018 Dennis Birkholz <dennis@birkholz.org>
 *
 * $Id$
 * Author:    $Format:%an <%ae>, %ai$
 * Committer: $Format:%cn <%ce>, %ci$
 */

namespace Iqb\Ecryptfs;


class FileHeaderTest extends \PHPUnit_Framework_TestCase
{
    private $passphrase = 'testtest';
    private $testfile = __DIR__ . '/data/encrypted/ECRYPTFS_FNEK_ENCRYPTED.FWYfdVWu0L3WzkakI4q9u3Q6AnT7JXlK1y60Vqyn5jsDHcG6MURT9qDmVE--';

    public function testParse()
    {
        $cryptoEngine = new OpenSslCryptoEngine();
        $fekek = Util::deriveFEKEK($this->passphrase);
        $file = \fopen($this->testfile, 'r');

        $fileHeader = FileHeader::parse($file, $cryptoEngine, $fekek);
        $this->assertSame(7, $fileHeader->size);
    }

    public function testGenerate()
    {
        $cryptoEngine = new OpenSslCryptoEngine();
        $fekek = Util::deriveFEKEK($this->passphrase);
        $file = \fopen($this->testfile, 'r');
        $fileHeader = FileHeader::parse($file, $cryptoEngine, $fekek);

        $testFileHeader = new FileHeader($fileHeader->size, $fileHeader->cipherCode, $fileHeader->fileKey);
        $testFileHeader->marker = $fileHeader->marker;
        $this->assertSame(
            \bin2hex(\file_get_contents($this->testfile, false, null, 0, $fileHeader->metadataSize)),
            \bin2hex($testFileHeader->generate($cryptoEngine, $fekek))
        );
    }
}
