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
class ManagerTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     */
    public function testKeyManagement()
    {
        $manager = new Manager();
        $manager->usePassphrase('test');
        
        $fekek = 'd395309aaad4de06';
        $fnek = 'be877764c5918621';
        $keys_ref = [
            // File encryption key encryption key (aka data key) for passphrase "test"
             $fekek => '58116605277520b3fa1315497f2089514d53100b08096ee8ab2c752c96ebfc7e8d270fce370c29b1afe1cde71ec6218c6fa62b7500b3b14e7456b6f53eb38580',
            
            // File name encryption key for passphrase "test" 
            $fnek => 'ac4007120f27ff0d0c30ce723432d13c24dccb0c0a4e3b5ae4beece867b1968685ff009e5fb62960b904ec7f0d853447f11c1a75d63b97fb98b3f4ee374052f8',
        ];
        
        $this->assertEquals($keys_ref, $manager->getKeys());
        $this->assertEquals($fekek, $manager->getDefaultFEKEK());
        $this->assertEquals($keys_ref[$fekek], $manager->getKey($fekek));
        $this->assertEquals($fnek, $manager->getDefaultFNEK());
        $this->assertEquals($keys_ref[$fnek], $manager->getKey($fnek));
    }
    
    /**
     * @test
     */
    public function testDecryptFilename()
    {
        $manager = new Manager();
        $manager->usePassphrase('test');
        
        $names = [
            "ECRYPTFS_FNEK_ENCRYPTED.FWayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJmz2V58c8wgb5UiUhMwEdok--" => "a filename.txt",
            "ECRYPTFS_FNEK_ENCRYPTED.FXayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJeRV3PRUhjTfza-to3TubMHz-pjq93YvUYPB0LUQxtDk-" => "another file.pdf",
            "ECRYPTFS_FNEK_ENCRYPTED.FXayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJCUa6.nXv4qOGpN5vz9sDHdzgUt6ewfDTuJM2wpHxEmc-" => "the F1n4l T3st.docx",
        ];
        
        foreach ($names as $encname => $decname) {
            $filename = $manager->decryptFilename($encname);
            $this->assertEquals($decname, $filename);
        }
    }
}
