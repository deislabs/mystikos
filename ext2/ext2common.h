#ifndef _EXT2COMMON_H
#define _EXT2COMMON_H

#include <myst/defs.h>
#include <myst/ext2.h>
#include <stdint.h>

MYST_INLINE bool ext2_test_bit(
    const uint8_t* data,
    uint32_t size,
    uint32_t index)
{
    uint32_t byte = index / 8;
    uint32_t bit = index % 8;
    return ((uint32_t)(data[byte]) & (1 << bit));
}

extern const uint8_t ext2_count_bits_table[];

MYST_INLINE uint32_t ext2_count_bits(uint8_t byte)
{
    return ext2_count_bits_table[byte];
}

uint32_t ext2_count_bits_n(const uint8_t* data, uint32_t size);

MYST_INLINE uint32_t
ext2_make_ino(const ext2_t* ext2, uint32_t grpno, uint32_t lino)
{
    return (grpno * ext2->sb.s_inodes_per_group) + (lino + 1);
}

#endif /* _EXT2COMMON_H */
