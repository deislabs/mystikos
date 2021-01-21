// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PUBKEY_H
#define _MYST_PUBKEY_H

#include <stdint.h>

int myst_pubkey_verify(
    const void* cpio_data,
    size_t cpio_size,
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* signer,
    size_t signer_size,
    const uint8_t* signature,
    size_t signature_size);

#endif /* _MYST_PUBKEY_H */
