// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HEX_H
#define _MYST_HEX_H

#include <stddef.h>
#include <stdint.h>

void myst_hexdump(const char* label, const void* data, size_t size);

ssize_t myst_ascii_to_bin(const char* s, uint8_t* buf, size_t buf_size);

#endif /* _MYST_HEX_H */
