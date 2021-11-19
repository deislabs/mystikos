// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HEX_H
#define _MYST_HEX_H

#include <stddef.h>
#include <stdint.h>

void myst_hexdump(const char* label, const void* data, size_t size);

void myst_ascii_dump(const char* label, const uint8_t* data, uint32_t size);

ssize_t myst_ascii_to_bin(const char* s, uint8_t* buf, size_t buf_size);

int myst_bin_to_ascii(
    const void* data,
    size_t size,
    char* buf,
    size_t buf_size);

#endif /* _MYST_HEX_H */
