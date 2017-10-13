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
class IntegrationTest extends TestCase
{
    /**
     * @var string
     */
    private $dataDir = __DIR__ . '/data';

    /**
     * @var string
     */
    private $integrationDir = __DIR__ . '/integration';

    /**
     * @var string
     */
    private $encryptedDir;

    /**
     * @var string
     */
    private $decryptedDir;

    /**
     * @var CryptoEngineInterface
     */
    private $cryptoEngine;

    /**
     * @var string
     */
    private $passphrase;

    /**
     * @var string
     */
    private $fnek;

    /**
     * @var string
     */
    private $fekek;


    protected function setUp()
    {
        $this->encryptedDir = \realpath($this->integrationDir . '/lower');
        $this->decryptedDir = \realpath($this->integrationDir . '/upper');
        $this->passphrase = \str_replace(['+', '=', '/'], '', \base64_encode(\random_bytes(32)));;
        $this->cryptoEngine = new OpenSslCryptoEngine();
        $this->fnek = Util::deriveFNEK($this->passphrase);
        $this->fekek = Util::deriveFEKEK($this->passphrase);

        $this->tearDown();

        // Insert passphrase into kernel keyring
        if (!$this->executeCommand(
            'echo -n %s | ecryptfs-add-passphrase --fnek -',
            $this->passphrase
        )) {
            throw new \RuntimeException("Failed to insert passphrase into kernel keyring.");
        }
    }


    protected function tearDown()
    {
        // Unmount ecryptfs directory
        $this->executeCommand(
            'mountpoint -q -- %s && ' . (\posix_getuid() !== 0 ? 'sudo ' : '') . 'umount -f %s || true',
            $this->decryptedDir,
            $this->decryptedDir
        );

        // Cleanup kernel keyring
        $this->executeCommand("keyctl clear @u");

        foreach (\glob($this->encryptedDir . '/' . Util::FNEK_ENCRYPTED_FILENAME_PREFIX . '*') as $file) {
            unlink($file);
        }
    }


    private function executeCommand($cmd, ...$args) : bool
    {
        $escapedArgs = [];
        foreach ($args as $arg) {
            $escapedArgs[] = \escapeshellarg($arg);
        }
        if (\count($escapedArgs)) {
            $fullCmd = \sprintf($cmd, ...$escapedArgs);
        } else {
            $fullCmd = $cmd;
        }

        $retval = 0;
        $output = [];

        //echo "Executing: '$fullCmd'\n";

        \exec($fullCmd, $output, $retval);
        if ($retval !== 0) {
            throw new \RuntimeException("Command '$fullCmd' failed with error $retval:\n" . \implode("\n", $output));
        }

        return true;
    }


    /**
     * @test
     */
    public function testAES256Integration()
    {
        $cipher = 'aes';
        $cipherBytes = '32';

        // Mount ecryptfs folder
        $this->assertTrue(
            $this->executeCommand(
                (\posix_getuid() !== 0 ? 'sudo ' : '') . 'mount -i -t ecryptfs -o %s %s %s',
                \sprintf(
                    'ecryptfs_sig=%s,ecryptfs_fnek_sig=%s,ecryptfs_cipher=%s,ecryptfs_key_bytes=%u,ecryptfs_unlink_sigs,ecryptfs_passthrough=yes',
                    Util::calculateSignature($this->fekek),
                    Util::calculateSignature($this->fnek),
                    $cipher,
                    $cipherBytes
                ),
                $this->encryptedDir,
                $this->decryptedDir
            )
        );

        // Copy sample file onto decrypted ecyptfs mount
        $sourceName = $this->dataDir . '/decrypted/loremipsum.txt';
        $this->assertTrue(copy($sourceName, $this->decryptedDir . '/' . \basename($sourceName)));

        // Verify a single file was created in the ecryptfs mount, try to decrypt the filename and match it against the original name
        $files = \glob($this->encryptedDir . '/' . Util::FNEK_ENCRYPTED_FILENAME_PREFIX . '*');
        $this->assertCount(1, $files);
        $this->assertEquals(\basename($sourceName), Util::decryptFilename($this->cryptoEngine, \basename($files[0]), $this->fnek));

        // Encrypt the filename of the sample file and very the ecryptfs mount created the same name
        $encryptedSourceName = Util::encryptFilename($this->cryptoEngine, \basename($sourceName), $this->fnek);
        $this->assertTrue(\file_Exists($this->encryptedDir . '/' . $encryptedSourceName), \sprintf("File %s not found, got only %s, passphase was %s", $encryptedSourceName, $files[0], $this->passphrase));

        // Decrypt sample file and compare it to original data
        $context = \stream_context_create([ StreamWrapper::STREAM_NAME => [ 'passphrase' => $this->passphrase ]]);
        $data = \file_get_contents(StreamWrapper::STREAM_NAME . '://' . $files[0], null, $context);
        $this->assertEquals(\file_get_contents($sourceName), $data);
    }
}
