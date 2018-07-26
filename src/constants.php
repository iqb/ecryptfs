<?php

/*
 * This file is part of the PHP EcryptFS library.
 * (c) 2017 by Dennis Birkholz
 * All rights reserved.
 * For the license to use this library, see the provided LICENSE file.
 */

namespace Iqb\Ecryptfs;

// From OpenPGP rfc
// see: https://tools.ietf.org/html/rfc2440#section-9.2
//      https://tools.ietf.org/html/rfc4880#section-9.2

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n45
 */
const RFC2440_CIPHER_RSA      = 0x01;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n36
 */
const RFC2440_CIPHER_DES3_EDE = 0x02;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n37
 */
const RFC2440_CIPHER_CAST_5   = 0x03;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n38
 */
const RFC2440_CIPHER_BLOWFISH = 0x04;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n39
 */
const RFC2440_CIPHER_AES_128  = 0x07;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n40
 */
const RFC2440_CIPHER_AES_192  = 0x08;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n41
 */
const RFC2440_CIPHER_AES_256  = 0x09;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n42
 */
const RFC2440_CIPHER_TWOFISH  = 0x0a;

/**
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n43
 */
const RFC2440_CIPHER_CAST_6   = 0x0b;

/**
 * Number of raw bytes used from signature hash
 *
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n28
 * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/include/ecryptfs.h#L73
 */
const ECRYPTFS_SIG_SIZE = 8;

/**
 * Size of the salt to use when deriving keys from the passphrase
 *
 * @link https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/ecryptfs.h#n23
 * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/include/ecryptfs.h#L73
 * @link http://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/libecryptfs/main.c#L214
 */
const ECRYPTFS_SALT_SIZE = 8;
