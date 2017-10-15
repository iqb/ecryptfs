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
    const CIPHER_MAPPING = [
        "aes" => [
            16 => RFC2440_CIPHER_AES_128,
            24 => RFC2440_CIPHER_AES_192,
            32 => RFC2440_CIPHER_AES_256,
        ],
        'blowfish' => RFC2440_CIPHER_BLOWFISH,
        'twofish' => RFC2440_CIPHER_TWOFISH,
        'cast5' => RFC2440_CIPHER_CAST_5,
        'cast6' => RFC2440_CIPHER_CAST_6,
        '3des' => RFC2440_CIPHER_DES3_EDE,
    ];

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
        $this->cryptoEngine = new OpenSslCryptoEngine();

        $this->tearDown();
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

        echo "Executing: '$fullCmd'\n";

        \exec($fullCmd, $output, $retval);
        if ($retval !== 0) {
            throw new \RuntimeException("Command '$fullCmd' failed with error $retval:\n" . \implode("\n", $output));
        }

        return true;
    }


    /**
     * Generates all possible combinations of ciphers and key sizes
     */
    public function integrationDataProvider()
    {
        $ciphers = [
            ['aes', 16], // AES 128
            ['aes', 24], // AES 192
            ['aes', 32], // AES 256
        ];

        $passwords = [
            // This passphrase will generate a "random prefix" in the TAG70 packet that contains a NULL-byte if not properly replaced.
            'HmPR65GG1nFFBHh1PdQMIGQ7vatEmi2c3qgqxZs3zk',
        ];

        for ($i=0; $i<5; $i++) {
            $passwords[] = \str_replace(['+', '=', '/'], '', \base64_encode(\random_bytes(32)));
        }

        $runs = [];

        foreach ($passwords as $password) {
            foreach ($ciphers as list($fnekCipher, $fnekCipherBytes)) {
                foreach ($ciphers as list($fekekCipher, $fekekCipherBytes)) {
                    // AES192 FEK is silently upgraded to AES256, so ignore it
                    // @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/ecryptfs/keystore.c?h=v4.11.3#n2241
                    if ($fekekCipher === "aes" && $fekekCipherBytes === 24) {
                        continue;
                    }

                    $runs["Passphrase: {$password}, FNEK: $fnekCipher " . ($fnekCipherBytes*8) . " bit, FEKEK: $fekekCipher " . ($fekekCipherBytes*8) . " bit"] = [$password, $fnekCipher, $fnekCipherBytes, $fekekCipher, $fekekCipherBytes];
                }
            }
        }

        return $runs;
    }

    /**
     * @test
     * @dataProvider integrationDataProvider
     */
    public function testIntegration(string $passphrase, string $fnekCipher, int $fnekCipherBytes, string $fekekCipher, int $fekekCipherBytes)
    {
        $fnek = Util::deriveFNEK($passphrase);
        $fekek = Util::deriveFEKEK($passphrase);

        // Insert passphrase into kernel keyring
        if (!$this->executeCommand(
            'echo -n %s | ecryptfs-add-passphrase --fnek -',
            $passphrase
        )) {
            throw new \RuntimeException("Failed to insert passphrase into kernel keyring.");
        }


        $fnekCipherCode = (\is_array(self::CIPHER_MAPPING[$fnekCipher]) ? self::CIPHER_MAPPING[$fnekCipher][$fnekCipherBytes] : self::CIPHER_MAPPING[$fnekCipher]);
        $fekekCipherCode = (\is_array(self::CIPHER_MAPPING[$fekekCipher]) ? self::CIPHER_MAPPING[$fekekCipher][$fekekCipherBytes] : self::CIPHER_MAPPING[$fekekCipher]);

        // Mount ecryptfs folder
        $this->assertTrue(
            $this->executeCommand(
                (\posix_getuid() !== 0 ? 'sudo ' : '') . 'mount -i -t ecryptfs -o %s %s %s',
                \sprintf(
                    'ecryptfs_fnek_sig=%s,ecryptfs_fn_cipher=%s,ecryptfs_fn_key_bytes=%u,ecryptfs_sig=%s,ecryptfs_cipher=%s,ecryptfs_key_bytes=%u,ecryptfs_unlink_sigs',
                    Util::calculateSignature($fnek),
                    $fnekCipher,
                    $fnekCipherBytes,
                    Util::calculateSignature($fekek),
                    $fekekCipher,
                    $fekekCipherBytes
                ),
                $this->encryptedDir,
                $this->decryptedDir
            )
        );

        foreach(['test', 'loremipsum.txt'] as $file) {
            // Copy sample file onto decrypted ecyptfs mount
            $sourceName = $this->dataDir . '/decrypted/' . $file;
            $this->assertTrue(copy($sourceName, $this->decryptedDir . '/' . $file));

            // Verify a single file was created in the ecryptfs mount, try to decrypt the filename and match it against the original name
            $files = \glob($this->encryptedDir . '/' . Util::FNEK_ENCRYPTED_FILENAME_PREFIX . '*');
            $this->assertCount(1, $files);
            $this->assertEquals($file, Util::decryptFilename($this->cryptoEngine, \basename($files[0]), $fnek));

            // Encrypt the filename of the sample file and very the ecryptfs mount created the same name
            $encryptedSourceName = Util::encryptFilename($this->cryptoEngine, $file, $fnek, $fnekCipherCode, $fnekCipherBytes);
            $this->assertTrue(\file_Exists($this->encryptedDir . '/' . $encryptedSourceName), \sprintf("File %s not found, got only %s, passphase was %s", $encryptedSourceName, \basename($files[0]), $passphrase));

            // Decrypt sample file and compare it to original data
            $context = \stream_context_create([ StreamWrapper::STREAM_NAME => [ 'passphrase' => $passphrase ]]);
            $data = \file_get_contents(StreamWrapper::STREAM_NAME . '://' . $files[0], null, $context);
            $this->assertEquals(\file_get_contents($sourceName), $data);

            unlink($this->decryptedDir . '/' . $file);
        }

    }
}
