#ifndef _MYST_BYTEORDER_H
#define _MYST_BYTEORDER_H

#include <stdbool.h>
#include <stdint.h>

static __inline__ bool myst_is_big_endian(void)
{
#if defined(__i386) || defined(__x86_64)
    return false;
#else
    typedef union un
    {
        unsigned short x;
        unsigned char bytes[2];
    }
    un;
    static un u = { 0xABCD };
    return u.bytes[0] == 0xAB ? true : false;
#endif
}

static __inline__ uint64_t myst_swap_u64(uint64_t x)
{
    if (myst_is_big_endian())
    {
        return x;
    }
    else
    {
        return ((uint64_t)((x & 0xFF) << 56)) |
               ((uint64_t)((x & 0xFF00) << 40)) |
               ((uint64_t)((x & 0xFF0000) << 24)) |
               ((uint64_t)((x & 0xFF000000) << 8)) |
               ((uint64_t)((x & 0xFF00000000) >> 8)) |
               ((uint64_t)((x & 0xFF0000000000) >> 24)) |
               ((uint64_t)((x & 0xFF000000000000) >> 40)) |
               ((uint64_t)((x & 0xFF00000000000000) >> 56));
    }
}

static __inline__ uint32_t myst_swap_u32(uint32_t x)
{
    if (myst_is_big_endian())
    {
        return x;
    }
    else
    {
        return ((uint32_t)((x & 0x000000FF) << 24)) |
               ((uint32_t)((x & 0x0000FF00) << 8)) |
               ((uint32_t)((x & 0x00FF0000) >> 8)) |
               ((uint32_t)((x & 0xFF000000) >> 24));
    }
}

static __inline__ int16_t myst_swap_u16(int16_t x)
{
    if (myst_is_big_endian())
    {
        return x;
    }
    else
    {
        return ((int16_t)((x & 0x00FF) << 8)) | ((int16_t)((x & 0xFF00) >> 8));
    }
}

#endif /* _MYST_BYTEORDER_H */
