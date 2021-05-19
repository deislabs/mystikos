// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BITS_H
#define _MYST_BITS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

MYST_INLINE
uint32_t myst_count_one_bits_u32(uint32_t x)
{
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x & 0x0F0F0F0F) + ((x >> 4) & 0x0F0F0F0F);
    x = (x & 0x00FF00FF) + ((x >> 8) & 0x00FF00FF);
    x = (x & 0x0000FFFF) + ((x >> 16) & 0x0000FFFF);
    return x & 0x3F;
}

MYST_INLINE
uint32_t myst_count_zero_bits_u32(uint32_t x)
{
    return 32 - myst_count_one_bits_u32(x);
}

MYST_INLINE
size_t myst_count_zero_bits(const uint8_t* bits, size_t nbits)
{
    size_t i = 0;
    size_t n = 0;

    if (((ptrdiff_t)bits % 4) == 0)
    {
        const uint32_t* p = (const uint32_t*)bits;
        size_t m = nbits / 32;

        while (m--)
        {
            n += myst_count_zero_bits_u32(*p);
            i += 32;
            p++;
        }
    }

    for (; i < nbits; i++)
    {
        if (!myst_test_bit(bits, i))
            n++;
    }

    return n;
}

MYST_INLINE
size_t myst_count_one_bits(const uint8_t* bits, size_t nbits)
{
    size_t i = 0;
    size_t n = 0;

    if (((ptrdiff_t)bits % 4) == 0)
    {
        const uint32_t* p = (const uint32_t*)bits;
        size_t m = nbits / 32;

        while (m--)
        {
            n += myst_count_one_bits_u32(*p);
            i += 32;
            p++;
        }
    }

    for (; i < nbits; i++)
    {
        if (myst_test_bit(bits, i))
            n++;
    }

    return n;
}

MYST_INLINE size_t
myst_skip_zero_bits(const uint8_t* bits, size_t nbits, size_t lo, size_t hi)
{
    size_t i = lo;

    (void)nbits;

    /* skip zero bits up to the next multiple of 8 or until exhausted */
    {
        size_t i_round = (i + 7) & ((size_t)-8);
        size_t min = (i_round < hi) ? i_round : hi;

        while (i < min && !myst_test_bit(bits, i))
            i++;

        /* if non-zero bit was found */
        if (i != min)
            return i;
    }

    /* skip over whole bytes if i is a multiple of 8 bits */
    if ((i % 8) == 0)
    {
        while (i + 8 < hi && bits[i / 8] == 0)
            i += 8;
    }

    while (i < hi && !myst_test_bit(bits, i))
        i++;

    return i;
}

MYST_INLINE
size_t myst_skip_one_bits(const uint8_t* bits, size_t nbits, size_t i)
{
    if (i == nbits)
        return nbits;

    /* round i to the next multiple of r */
    const size_t r = 64;
    const size_t m = (i + r - 1) / r * r;

    /* if i is not aligned, then process bits up to next r-bit alignement */
    if (i != m)
    {
        /* skip bits up to next r-bit alignment */
        while (i < m && myst_test_bit(bits, i))
            i++;

        if (i == nbits)
            return i;

        if (myst_test_bit(bits, i) == 0)
            return i;
    }

    /* skip over 8 bytes at a time */
    {
        size_t r = nbits - i;

        while (r > 64 && *((uint64_t*)&bits[i / 8]) == 0xffffffffffffffff)
        {
            i += 64;
            r -= 64;
        }
    }

    /* handle any remaining bits */
    while (i < nbits && myst_test_bit(bits, i))
        i++;

    return i;
}

MYST_INLINE
void myst_set_bits(uint8_t* bits, size_t nbits, size_t lo, size_t hi)
{
    size_t i = lo;
    size_t r = (lo + 7) / 8 * 8;
    const size_t min = (r < hi) ? r : hi;

    (void)nbits;

    /* set bits up to the first multile of 8 */
    for (; i < min; i++)
        myst_set_bit(bits, i);

    /* set whole bytes */
    {
        size_t nbits = hi - min;

        if (nbits)
        {
            uint8_t* p = &bits[i / 8];
            size_t nbytes = nbits / 8;
            memset(p, 0xff, nbytes);
            i += nbytes * 8;
        }
    }

    /* set bits after the last multile of 8 */
    for (; i < hi; i++)
        myst_set_bit(bits, i);
}

MYST_INLINE
void myst_clear_bits(uint8_t* bits, size_t nbits, size_t lo, size_t hi)
{
    size_t i = lo;
    size_t r = (lo + 7) / 8 * 8;
    const size_t min = (r < hi) ? r : hi;

    (void)nbits;

    /* clear bits up to the first multile of 8 */
    for (; i < min; i++)
        myst_clear_bit(bits, i);

    /* clear whole bytes */
    {
        size_t nbits = hi - min;

        if (nbits)
        {
            uint8_t* p = &bits[i / 8];
            size_t nbytes = nbits / 8;
            memset(p, 0, nbytes);
            i += nbytes * 8;
        }
    }

    /* clear bits after the last multile of 8 */
    for (; i < hi; i++)
        myst_clear_bit(bits, i);
}

#endif /* _MYST_BITS_H */
