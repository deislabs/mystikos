// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ROOTHASH_H
#define _MYST_ROOTHASH_H

#include <stdint.h>

int myst_roothash_verify(
    const void* cpio_data,
    size_t cpio_size,
    const uint8_t* roothash,
    size_t roothash_size);

#endif /* _MYST_ROOTHASH_H */
