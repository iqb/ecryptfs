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
        
        $keys_ref = [
            // File encryption key encryption key (aka data key) for passphrase "test"
            'd395309aaad4de06' => '58116605277520b3fa1315497f2089514d53100b08096ee8ab2c752c96ebfc7e8d270fce370c29b1afe1cde71ec6218c6fa62b7500b3b14e7456b6f53eb38580',
            
            // File name encryption key for passphrase "test" 
            'be877764c5918621' => 'ac4007120f27ff0d0c30ce723432d13c24dccb0c0a4e3b5ae4beece867b1968685ff009e5fb62960b904ec7f0d853447f11c1a75d63b97fb98b3f4ee374052f8',
        ];
        
        $this->assertEquals($keys_ref, $manager->getKeys());
    }
}
