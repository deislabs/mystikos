// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BITS_H
#define _MYST_BITS_H

#include <stddef.h>

#include <myst/defs.h>

MYST_INLINE bool myst_test_bit(const uint8_t* data, size_t index)
{
    const size_t byte = index / 8;
    const size_t bit = index % 8;
    return (data[byte] & (uint8_t)(1 << bit)) ? 1 : 0;
}

MYST_INLINE void myst_set_bit(uint8_t* data, size_t index)
{
    const size_t byte = index / 8;
    const size_t bit = index % 8;
    data[byte] |= (uint8_t)(1 << bit);
}

MYST_INLINE void myst_clear_bit(uint8_t* data, size_t index)
{
    const size_t byte = index / 8;
    const size_t bit = index % 8;
    data[byte] &= (uint8_t) ~(1 << bit);
}

#endif /* _MYST_BITS_H */
