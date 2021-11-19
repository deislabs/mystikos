// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CRYPT_H
#define _MYST_CRYPT_H

#include <stdint.h>

/* 512-bit key */
typedef struct myst_key_512
{
    uint8_t data[512 / 8];
} myst_key_512_t;

int myst_encrypt_aes_256_xts(
    const myst_key_512_t* key,
    const void* data_in,
    void* data_out,
    size_t data_size,
    uint64_t counter); /* counter used in the initialization vector */

int myst_decrypt_aes_256_xts(
    const myst_key_512_t* key,
    const void* data_in,
    void* data_out,
    size_t data_size,
    uint64_t counter); /* counter used in the initialization vector */

#endif /* _MYST_CRYPT_H */
