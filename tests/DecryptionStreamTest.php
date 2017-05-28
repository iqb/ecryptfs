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
class DecryptionStreamTest extends \PHPUnit\Framework\TestCase
{
    public function testDecryption()
    {
        $basedir = __DIR__ . '/data';
        
        $manager = new Manager();
        $manager->usePassphrase('test');
        
        $files = [
            'encrypted/ECRYPTFS_FNEK_ENCRYPTED.FWayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJwLxTOkMu8UtE6MkSWHGsZE--' => 'decrypted/test',
            'encrypted/ECRYPTFS_FNEK_ENCRYPTED.FWayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJZ7NYS7ANeS4Gfi9c34ZDTU--' => 'decrypted/loremipsum.txt',
        ];
        
        foreach ($files as $encfile => $decfile) {
            $enc = '';
            $dec = \file_get_contents($basedir . '/' . $decfile);
            
            $fp = \fopen($basedir . '/' . $encfile, 'r');
            $decryptionStream = new DecryptionStream($manager, $fp);
            
            do {
                $enc .= $decryptionStream->read();
            } while (\strlen($enc) < strlen($dec));
            
            $this->assertEquals($dec, $enc);
        }
    }
}
