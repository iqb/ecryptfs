[![Build Status](https://travis-ci.org/iqb/ecryptfs.png?branch=master)](https://travis-ci.org/iqb/ecryptfs)
[![Scrutinizer Score](https://scrutinizer-ci.com/g/iqb/ecryptfs/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/iqb/ecryptfs)
[![Code Coverage](https://scrutinizer-ci.com/g/iqb/ecryptfs/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/iqb/ecryptfs)

Userland EcryptFS library written in PHP
========================================

[EcryptFS](http://ecryptfs.org/) is a Linux file system that allows you encrypt your files (and filenames).
It is part of the Linux Kernel and is used e.g. by Ubuntu to encrypt users home directories.

EcryptFS uses two (possibly different) keys for encryption:
- the FNEK (File Name Encryption Key) for encrypting/decrypting files names
- the FEKEK (File Encryption Key Encryption Key) for encrypting/decryption the file specific random key the file contents is encrypted with 

By default, these two keys are derived from a passphrase.

Encrypting/Decrypting file names
--------------------------------

Encrypted file names start with the prefix `ECRYPTFS_FNEK_ENCRYPTED.` followed by the encrypted original file name.
E.g. `ECRYPTFS_FNEK_ENCRYPTED.FWayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJZ7NYS7ANeS4Gfi9c34ZDTU--` decrypts to `loremipsum.txt` you use the passphrase `test`.

The code for encrypting and decrypting file names looks like this:

```php
<?php
    require_once(__DIR__ . '/vendor/autoload.php');
    
    $passphrase = 'test';
    // We need to derive the File Name Encryption key from the passphrase        
    $fnek = \Iqb\Ecryptfs\Util::deriveFNEK($passphrase);
    // We need a crypto engine to do the work (currently only OpenSSL)
    $cryptoEngine = new \Iqb\Ecryptfs\OpenSslCryptoEngine();
    
    $filename = 'loremipsum.txt';
    $encryptedFilename = \Iqb\Ecryptfs\Util::encryptFilename($cryptoEngine, $filename, $fnek);
    // Should output 'ECRYPTFS_FNEK_ENCRYPTED.FWayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJZ7NYS7ANeS4Gfi9c34ZDTU--'
    echo $encryptedFilename, PHP_EOL;
                     
    // And the reverse operation should return the original file name
    if (\Iqb\Ecryptfs\Util::decryptFilename($cryptoEngine, $filename, $fnek) !== $filename) {
        throw new \RuntimeException("Decryption error");
    }
    
    // You can test whether a file name is encrypted or not by using the isEncryptedFilename method.
    // But this method will just check the prefix of the filename (but works even if the file name contains a directory):
    if (\Iqb\Ecryptfs\Util::isEncryptedFilename(\realpath($encryptedFilename))) {
        echo $encryptedFilename, " is an encrypted filename", PHP_EOL;        
    }
    
    if (!\Iqb\Ecryptfs\Util::isEncryptedFilename($filename)) {
        echo $filename, " is not an encrypted filename", PHP_EOL;        
    }
```

        
Decrypting file content
-----------------------

File decryption has only basic support currently.
Decryption is handled via the stream wrapper `ecryptfs://`.
The File Encryption Key Encryption Key (FEKEK) is derived from the supplied passphrase.

```php
<?php
    require_once(__DIR__ . '/vendor/autoload.php');
    
    // The passphrase to use
    $passphrase = 'test';
    
    // We must pass it as a stream context
    $context = \stream_context_create([
        'ecryptfs' => [
            'passphrase' => $passphrase,
        ]
    ]);
    
    // alternatively we could use constants to avoid typos:
    $context = \stream_context_create([
        \Iqb\Ecryptfs\StreamWrapper::STREAM_NAME => [
            \Iqb\Ecryptfs\StreamWrapper::CONTEXT_PASSPHRASE => $passphrase,
        ]
    ]);
    
    // This will print some lorem ipsum text
    echo \file_get_contents('ecryptfs://' . __DIR__ . '/tests/data/encrypted/ECRYPTFS_FNEK_ENCRYPTED.FWayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJZ7NYS7ANeS4Gfi9c34ZDTU--', null, $context), PHP_EOL;
```

Everything after the `ecryptfs://` and the stream context is passed to `fopen()` so you can access encrypted files with all available stream wrappers in PHP.

If you don't have a file put an open resource (e.g. a file opened via HTTP by Guzzle), you can pass the resource via the stream context:

```php
<?php
    require_once(__DIR__ . '/vendor/autoload.php');
    
    // The passphrase to use
    $passphrase = 'test';
    
    // Open the file directly or use a handle from somewhere else:
    $stream_resource = \fopen(__DIR__ . '/tests/data/encrypted/ECRYPTFS_FNEK_ENCRYPTED.FWayVrRYlN446EY.WUc7GBFqG9GB6qF3eRmJZ7NYS7ANeS4Gfi9c34ZDTU--', 'r');
    
    // And pass the stream resource via the stream context
    $context = \stream_context_create([
        \Iqb\Ecryptfs\StreamWrapper::STREAM_NAME => [
            \Iqb\Ecryptfs\StreamWrapper::CONTEXT_PASSPHRASE => $passphrase,
            \Iqb\Ecryptfs\StreamWrapper::CONTEXT_STREAM => $stream_resource,
        ]
    ]);
    
    // This will print some lorem ipsum text
    // Everything after the 'ecryptfs://' is ignored
    echo \file_get_contents('ecryptfs://', null, $context), PHP_EOL;
```

Limitations
-----------

- Seeking in the decrypted file content is not supported yet
- Encrypting files is not possible yet
- Currently only AES (with 128 and 256 bits) are fully supported
- AES with 192 bits only works for file names (due to limitations in the original EcryptFS kernel implementation)
- If the randomly generated file encryption key (FEK) available for decryption with multiple FEKEKs (as is theoretically possible in the EcryptFS file header but not used AFAIK), only the first packet is tried. If it was encrypted with another FEKEK, the decryption will fail.  

Compatibility
-------------

To test compatibility with your specific version of EcryptFS just run the test suite with PHPUnit.
The IntegrationTest class creates real EcryptFS mounts and writes files to the mounts to verify the functionality.
That requires that the EcryptFS utilities package (e.g. ecryptfs-utils in Debian/Ubuntu) is installed and the tests
are run by root or sudo without password is executable. 

The library is developed on Debian Stretch with Kernel 4.9 but is at least compatible with the EcryptFS versions in Debian Jessie, the CI tests run on Ubuntu AFAIK.
The EcryptFS on disk format seems pretty stable to the chances for incompatibilities with future Kernel Versions is quite slim.
