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
    return ((size_t)(data[byte]) & (1 << bit)) ? 1 : 0;
}

MYST_INLINE void myst_set_bit(uint8_t* data, size_t index)
{
    const size_t byte = index / 8;
    const size_t bit = index % 8;
    data[byte] |= (1 << bit);
}

MYST_INLINE void myst_clear_bit(uint8_t* data, size_t index)
{
    const size_t byte = index / 8;
    const size_t bit = index % 8;
    data[byte] &= ~(1 << bit);
}

MYST_INLINE size_t
myst_find_clear_bit(uint8_t* data, size_t size, size_t start_index)
{
    uint8_t i = start_index / 8;
    uint8_t val = 0;

    while (i < size)
    {
        val = data[i];
        if (val != 0xff)
        {
            return (i * 8 + (size_t)__builtin_ctz((int)(~val & (val + 1))));
        }
        i++;
    }
    return 0;
}
#endif /* _MYST_BITS_H */
