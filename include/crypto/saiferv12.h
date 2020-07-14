/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

 /* Copyright (c) 2017 National Security Research Institute.  All rights reserved. */

#ifndef OSSL_CRYPTO_SAIFERV12_H
# define OSSL_CRYPTO_SAIFERV12_H

# include <openssl/opensslconf.h>

# ifdef OPENSSL_NO_SAIFERV12
#  error SAIFERV12 is disabled.
# endif

# define SAIFERV12_ENCRYPT     1
# define SAIFERV12_DECRYPT     0

# define SAIFERV12_BLOCK_SIZE    16  /* Size of each encryption/decryption block */
# define SAIFERV12_MAX_KEYS      17  /* Number of keys needed in the worst case  */

typedef union {
    unsigned char c[SAIFERV12_BLOCK_SIZE];
    unsigned int u[SAIFERV12_BLOCK_SIZE / sizeof(unsigned int)];
} SAIFERV12_u128;

typedef unsigned char SAIFERV12_c128[SAIFERV12_BLOCK_SIZE];

struct saiferv12_key_st {
    SAIFERV12_u128 rd_key[SAIFERV12_MAX_KEYS];
    unsigned int rounds;
};
typedef struct saiferv12_key_st SAIFERV12_KEY;


int saiferv12_set_encrypt_key(const unsigned char *userKey, const int bits,
                         SAIFERV12_KEY *key);
int saiferv12_set_decrypt_key(const unsigned char *userKey, const int bits,
                         SAIFERV12_KEY *key);

void saiferv12_encrypt(const unsigned char *in, unsigned char *out,
                  const SAIFERV12_KEY *key);

#endif
