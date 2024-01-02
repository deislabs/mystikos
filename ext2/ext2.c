// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <time.h>

#include <myst/clock.h>
#include <myst/eraise.h>
#include <myst/ext2.h>
#include <myst/hex.h>
#include <myst/paths.h>
#include <myst/round.h>
#include <myst/strarr.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/uid_gid.h>
#include "ext2common.h"

#define EXT2_S_MAGIC 0xEF53

#define EXT2_SINGLE_INDIRECT_BLOCK 12
#define EXT2_DOUBLE_INDIRECT_BLOCK 13
#define EXT2_TRIPLE_INDIRECT_BLOCK 14

/* limit the stack size of the functions below */
#pragma GCC diagnostic error "-Wstack-usage=512"

#if 0
#define CHECKS
#endif

struct ext2_dir
{
    void* data;
    size_t size;
    const void* next;
    struct dirent ent;
};

#define FILE_MAGIC 0x0e6fc76762264945

struct myst_file_shared
{
    uint64_t magic;
    ext2_ino_t ino;
    ext2_inode_t inode;
    uint64_t offset;
    int open_flags;
    uint32_t access;    /* (O_RDONLY | O_RDWR | O_WRONLY | O_PATH) */
    uint32_t operating; /* (O_APPEND | O_DIRECT | O_NOATIME | O_NONBLOCK) */
    char realpath[PATH_MAX];
    ext2_dir_t dir;
    _Atomic(size_t) use_count;
};

/* file descriptor level object */
struct myst_file
{
    struct myst_file_shared* shared;
    int fdflags; /* file descriptor flags: FD_CLOEXEC */
};

MYST_UNUSED
static bool _valid_ino(const ext2_t* ext2, ext2_ino_t ino)
{
    return ino > 0 && ino <= ext2->sb.s_inodes_count;
}

static void _inode_ref(ext2_t* ext2, ext2_ino_t ino)
{
    assert(_valid_ino(ext2, ino));
    ext2->inode_refs[ino - 1].nopens++;
}

static ext2_ino_t _inode_unref(ext2_t* ext2, ext2_ino_t ino)
{
    assert(_valid_ino(ext2, ino));
    assert(ext2->inode_refs[ino - 1].nopens > 0);
    return --ext2->inode_refs[ino - 1].nopens;
}

static bool _file_shared_valid(const myst_file_shared_t* shared)
{
    return shared != NULL && shared->magic == FILE_MAGIC;
}

static bool _file_valid(const myst_file_t* file)
{
    return file != NULL && _file_shared_valid(file->shared);
}

static void _file_shared_clear(myst_file_shared_t* shared)
{
    memset(shared, 0xdd, sizeof(myst_file_shared_t));
}

static void _file_clear(myst_file_t* file)
{
    memset(file, 0xdd, sizeof(myst_file_t));
}

static void _file_shared_free(myst_file_shared_t* file_shared)
{
    if (file_shared)
    {
        assert(_file_shared_valid(file_shared));
        _file_shared_clear(file_shared);
        free(file_shared);
    }
}

static void _file_free(myst_file_t* file)
{
    if (file)
    {
        assert(_file_valid(file));
        _file_clear(file);
        free(file);
    }
}

static bool _ext2_valid(const ext2_t* ext2)
{
    return ext2 != NULL && ext2->sb.s_magic == EXT2_S_MAGIC;
}

static __inline__ uint32_t _next_mult(uint32_t x, uint32_t m)
{
    return (x + m - 1) / m * m;
}

static __inline__ uint32_t _min_u32(uint32_t x, uint32_t y)
{
    return x < y ? x : y;
}

static __inline__ size_t _min_size(size_t x, size_t y)
{
    return x < y ? x : y;
}

static __inline__ size_t _max_size(size_t x, size_t y)
{
    return x > y ? x : y;
}

static size_t _dirent_size(const ext2_dirent_t* ent)
{
    return _next_mult(
        sizeof(ext2_dirent_t) - EXT2_FILENAME_MAX + ent->name_len, 4);
}

static uint8_t _mode_to_file_type(uint16_t mode)
{
    if (S_ISREG(mode))
        return EXT2_FT_REG_FILE;
    if (S_ISDIR(mode))
        return EXT2_FT_DIR;
    if (S_ISCHR(mode))
        return EXT2_FT_CHRDEV;
    if (S_ISBLK(mode))
        return EXT2_FT_BLKDEV;
    if (S_ISFIFO(mode))
        return EXT2_FT_FIFO;
    if (S_ISSOCK(mode))
        return EXT2_FT_SOCK;
    if (S_ISLNK(mode))
        return EXT2_FT_SYMLINK;

    return EXT2_FT_UNKNOWN;
}

#define ACCESS 1
#define CHANGE 2
#define MODIFY 4

static void _update_timestamps(ext2_inode_t* inode, int flags)
{
    time_t t = time(NULL);

    assert(t <= UINT32_MAX);

    if (flags & ACCESS)
        inode->i_atime = t;

    if (flags & CHANGE)
        inode->i_ctime = t;

    if (flags & MODIFY)
        inode->i_mtime = t;
}

static void _dirent_init(
    ext2_dirent_t* ent,
    ext2_ino_t ino,
    uint8_t file_type,
    const char* filename)
{
    memset(ent, 0, sizeof(ext2_dirent_t));
    ent->inode = ino;
    ent->name_len = _min_size(strlen(filename), EXT2_FILENAME_MAX);
    memcpy(ent->name, filename, ent->name_len);
    ent->file_type = file_type;
    ent->rec_len = sizeof(ext2_dirent_t) - EXT2_FILENAME_MAX + ent->name_len;
    ent->rec_len = _next_mult(ent->rec_len, 4);
}

MYST_INLINE bool _zero_filled_u32(const uint32_t* s, size_t n)
{
    return myst_memcchr(s, 0, n * sizeof(uint32_t)) == NULL;
}

static ssize_t _read(myst_blkdev_t* dev, size_t offset, void* data, size_t size)
{
    ssize_t ret = -1;
    uint32_t blkno;
    uint32_t i;
    uint32_t rem;
    uint8_t* ptr;
    const size_t blksz = MYST_BLKSIZE;
    struct locals
    {
        uint8_t blk[MYST_BLKSIZE];
    };
    struct locals* locals = NULL;

    if (!dev || !data)
        goto done;

    /* calculate the block number */
    blkno = offset / MYST_BLKSIZE;

    /* optimize for common case where offset and size are divisible by blksz */
    if ((offset % blksz) == 0 && (size % blksz) == 0)
    {
        const size_t n = size / blksz;
        ptr = (uint8_t*)data;

        for (i = 0; i < n; i++)
        {
            if (dev->get(dev, i + blkno, ptr) != 0)
                goto done;

            ptr += blksz;
        }
    }
    else
    {
        if (!(locals = malloc(sizeof(struct locals))))
            goto done;

        for (i = blkno, rem = size, ptr = (uint8_t*)data; rem; i++)
        {
            uint32_t off; /* offset into this block */
            uint32_t len; /* bytes to read from this block */

            if (dev->get(dev, i, locals->blk) != 0)
                goto done;

            /* If first block */
            if (i == blkno)
                off = offset % MYST_BLKSIZE;
            else
                off = 0;

            len = MYST_BLKSIZE - off;

            if (len > rem)
                len = rem;

            memcpy(ptr, &locals->blk[off], len);
            rem -= len;
            ptr += len;
        }
    }

    ret = size;

done:

    if (locals)
        free(locals);

    return ret;
}

static ssize_t _write(
    myst_blkdev_t* dev,
    size_t offset,
    const void* data,
    size_t size)
{
    ssize_t ret = -1;
    uint32_t blkno;
    uint32_t i;
    uint32_t rem;
    uint8_t* ptr;
    const size_t blksz = MYST_BLKSIZE;
    struct locals
    {
        uint8_t blk[MYST_BLKSIZE];
    };
    struct locals* locals = NULL;

    if (!dev || !data)
        goto done;

    blkno = offset / blksz;

    /* optimize for common case where offset and size are divisible by blksz */
    if ((offset % blksz) == 0 && (size % blksz) == 0)
    {
        const size_t n = size / blksz;
        ptr = (uint8_t*)data;

        for (i = 0; i < n; i++)
        {
            if (dev->put(dev, i + blkno, ptr) != 0)
                goto done;

            ptr += blksz;
        }
    }
    else
    {
        if (!(locals = malloc(sizeof(struct locals))))
            goto done;

        for (i = blkno, rem = size, ptr = (uint8_t*)data; rem; i++)
        {
            uint32_t off; /* offset into this block */
            uint32_t len; /* bytes to write from this block */

            /* Fetch the block */
            if (dev->get(dev, i, locals->blk) != 0)
                goto done;

            /* If first block */
            if (i == blkno)
                off = offset % MYST_BLKSIZE;
            else
                off = 0;

            len = MYST_BLKSIZE - off;

            if (len > rem)
                len = rem;

            memcpy(&locals->blk[off], ptr, len);
            rem -= len;
            ptr += len;

            /* Rewrite the block */
            if (dev->put(dev, i, locals->blk) != 0)
                goto done;
        }
    }

    ret = size;

done:

    if (locals)
        free(locals);

    return ret;
}

const uint8_t ext2_count_bits_table[] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

uint32_t ext2_count_bits_n(const uint8_t* data, uint32_t size)
{
    uint32_t i;
    uint32_t n = 0;

    for (i = 0; i < size; i++)
    {
        n += ext2_count_bits(data[i]);
    }

    return n;
}

static __inline__ void _set_bit(uint8_t* data, uint32_t size, uint32_t index)
{
    uint32_t byte = index / 8;
    uint32_t bit = index % 8;

#ifdef CHECKS
    assert(byte < size);
#endif

    data[byte] |= (1 << bit);
}

static __inline__ void _clear_bit(uint8_t* data, uint32_t size, uint32_t index)
{
    uint32_t byte = index / 8;
    uint32_t bit = index % 8;

#ifdef CHECKS
    assert(byte < size);
#endif

    data[byte] &= ~(1 << bit);
}

/* Byte offset of this block (block 0 is the null block) */
static uint64_t _blk_offset(uint32_t blkno, uint32_t block_size)
{
    return (uint64_t)blkno * (uint64_t)block_size;
}

static uint32_t _make_blkno(const ext2_t* ext2, uint32_t grpno, uint32_t lblkno)
{
    const uint64_t first = ext2->sb.s_first_data_block;
    return (grpno * ext2->sb.s_blocks_per_group) + (lblkno + first);
}

static uint32_t _blkno_to_grpno(const ext2_t* ext2, uint32_t blkno)
{
    const uint64_t first = ext2->sb.s_first_data_block;

    if (first && blkno == 0)
        return 0;

    return (blkno - first) / ext2->sb.s_blocks_per_group;
}

static uint32_t _blkno_to_lblkno(const ext2_t* ext2, uint32_t blkno)
{
    const uint64_t first = ext2->sb.s_first_data_block;

    if (first && blkno == 0)
        return 0;

    return (blkno - first) % ext2->sb.s_blocks_per_group;
}

static uint64_t _inode_get_size(const ext2_inode_t* inode)
{
    const uint64_t lo = inode->i_size;
    const uint64_t hi = inode->i_dir_acl;
    return (hi << 32) | lo;
}

static void _inode_set_size(ext2_inode_t* inode, uint64_t size)
{
    inode->i_size = (uint32_t)(size & 0x00000000ffffffff);
    inode->i_dir_acl = (uint32_t)(size >> 32);
}

static void _init_block(ext2_block_t* block, uint32_t size)
{
    memset(block, 0, sizeof(ext2_block_t));
    block->size = size;
}

static int _write_block(
    const ext2_t* ext2,
    uint32_t blkno,
    const ext2_block_t* block)
{
    int ret = 0;
    size_t offset = _blk_offset(blkno, ext2->block_size);

#ifdef CHECK
    assert(block->size <= ext2->block_size);
#endif

    /* Write the block */
    if (_write(ext2->dev, offset, block->data, block->size) != block->size)
    {
        ERAISE(-EIO);
    }

    ret = 0;

done:

    return ret;
}

static int _write_group(const ext2_t* ext2, uint32_t grpno)
{
    int ret = 0;
    uint32_t blkno;

    if (ext2->block_size == 1024)
        blkno = 2;
    else
        blkno = 1;

    const size_t size = sizeof(ext2_group_desc_t);
    const size_t offset = _blk_offset(blkno, ext2->block_size) + (grpno * size);

    /* Read the block */
    if (_write(ext2->dev, offset, &ext2->groups[grpno], size) != size)
    {
        ERAISE(-EIO);
    }

done:

    return ret;
}

static int _write_super_block(const ext2_t* ext2)
{
    int ret = 0;
    const size_t size = sizeof(ext2_super_block_t);

    /* Read the superblock */
    if (_write(ext2->dev, EXT2_BASE_OFFSET, &ext2->sb, size) != size)
    {
        ERAISE(-EIO);
    }

    ret = 0;

done:
    return ret;
}

#ifdef CHECK
static int _check_blkno(
    ext2_t* ext2,
    uint32_t blkno,
    uint32_t grpno,
    uint32_t lblkno)
{
    int ret = 0;

    /* sanity check */
    if (_make_blkno(ext2, grpno, lblkno) != blkno)
        ERAISE(-EINVAL);

    /* see if 'grpno' is out of range */
    if (grpno > ext2->group_count)
        ERAISE(-EINVAL);

done:
    return ret;
}
#endif

static int _write_block_bitmap(
    const ext2_t* ext2,
    uint32_t group_index,
    const ext2_block_t* block)
{
    int ret = 0;
    uint32_t bitmap_size_bytes;

    bitmap_size_bytes = ext2->sb.s_blocks_per_group / 8;

    if (block->size != bitmap_size_bytes)
        ERAISE(-EINVAL);

    if (group_index > ext2->group_count)
        ERAISE(-EINVAL);

    ECHECK(
        _write_block(ext2, ext2->groups[group_index].bg_block_bitmap, block));

done:
    return ret;
}

static int _write_group_with_bitmap(
    ext2_t* ext2,
    uint32_t grpno,
    ext2_block_t* bitmap)
{
    int ret = 0;

    /* Write the group */
    ECHECK(_write_group(ext2, grpno));

    /* Write the bitmap */
    ECHECK(_write_block_bitmap(ext2, grpno, bitmap));

    ret = 0;

done:
    return ret;
}

/* comparison function for qsort */
static int _put_blkno(ext2_t* ext2, uint32_t blkno)
{
    int ret = 0;
    const uint32_t grpno = _blkno_to_grpno(ext2, blkno);
    const uint32_t lblkno = _blkno_to_lblkno(ext2, blkno);
    ext2_block_t* bitmap;

    if (!(bitmap = malloc(sizeof(ext2_block_t))))
        ERAISE(-ENOMEM);

#ifdef CHECK
    ECHECK(_check_blkno(ext2, blkno, grpno, lblkno));
#endif

    /* read the block bitmap */
    ECHECK(ext2_read_block_bitmap(ext2, grpno, bitmap));

#ifdef CHECK
    /* be sure the bit for this block number is actually set */
    if (!_test_bit(bitmap.data, bitmap.size, lblkno))
        ERAISE(-EINVAL);
#endif

    /* clear the bit for the block number */
    _clear_bit(bitmap->data, bitmap->size, lblkno);

    /* update the block count in the super block */
    ext2->sb.s_free_blocks_count++;

    /* update the group block count */
    ext2->groups[grpno].bg_free_blocks_count++;

    /* write the group and bitmap */
    ECHECK(_write_group_with_bitmap(ext2, grpno, bitmap));

    /* ATTN: minimize super block writes */
    /* update super block. */
    ECHECK(_write_super_block(ext2));

done:

    if (bitmap)
        free(bitmap);

    return ret;
}

static int _get_blkno(ext2_t* ext2, uint32_t* blkno)
{
    int ret = 0;
    struct locals
    {
        ext2_block_t bitmap;
    };
    struct locals* locals = NULL;
    uint32_t grpno;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Clear any block number */
    *blkno = 0;

    /* Use brute force search for a free block */
    for (grpno = 0; grpno < ext2->group_count; grpno++)
    {
        uint32_t lblkno;

        /* Read the bitmap */

        ECHECK(ext2_read_block_bitmap(ext2, grpno, &locals->bitmap));

        /* Scan the bitmap, looking for free bit */
        {
            const uint8_t* p;

            /* skip over full (0xff) bytes */
            p = myst_memcchr(locals->bitmap.data, 0xff, locals->bitmap.size);

            if (!p)
                continue;

            lblkno = (p - locals->bitmap.data) * 8;

            for (; lblkno < locals->bitmap.size * 8; lblkno++)
            {
                if (!ext2_test_bit(
                        locals->bitmap.data, locals->bitmap.size, lblkno))
                {
                    _set_bit(locals->bitmap.data, locals->bitmap.size, lblkno);
                    *blkno = _make_blkno(ext2, grpno, lblkno);
                    break;
                }
            }
        }

        if (*blkno)
            break;
    }

    /* If no free blocks found */
    if (!*blkno)
        ERAISE(-ENOSPC);

    /* Write the superblock */
    {
        ext2->sb.s_free_blocks_count--;
        ECHECK(_write_super_block(ext2));
    }

    /* Write the group */
    {
        ext2->groups[grpno].bg_free_blocks_count--;
        ECHECK(_write_group(ext2, grpno));
    }

    /* Write the bitmap */
    ECHECK(_write_block_bitmap(ext2, grpno, &locals->bitmap));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _read_super_block(myst_blkdev_t* dev, ext2_super_block_t* sb)
{
    int ret = 0;

    /* Read the superblock */
    if (_read(dev, EXT2_BASE_OFFSET, sb, sizeof(ext2_super_block_t)) !=
        sizeof(ext2_super_block_t))
    {
        ERAISE(-EIO);
    }

    ret = 0;

done:
    return ret;
}

static ext2_group_desc_t* _read_groups(const ext2_t* ext2)
{
    int ret = 0;
    ext2_group_desc_t* groups = NULL;
    uint32_t groups_size = 0;
    uint32_t blkno;

    /* Allocate the groups list */
    {
        groups_size = ext2->group_count * sizeof(ext2_group_desc_t);

        if (!(groups = (ext2_group_desc_t*)malloc(groups_size)))
        {
            ERAISE(-ENOMEM);
        }
    }

    /* Determine the block where group table starts */
    if (ext2->block_size == 1024)
        blkno = 2;
    else
        blkno = 1;

    /* Read the block */
    if (_read(
            ext2->dev,
            _blk_offset(blkno, ext2->block_size),
            groups,
            groups_size) != groups_size)
    {
        ERAISE(-EIO);
    }

done:

    if (ret)
    {
        if (groups)
        {
            free(groups);
            groups = NULL;
        }
    }

    return groups;
}

static uint32_t _ino_to_grpno(const ext2_t* ext2, ext2_ino_t ino)
{
#ifdef CHECK
    assert(ino != 0);
#endif

    return (ino - 1) / ext2->sb.s_inodes_per_group;
}

static uint32_t _ino_to_lino(const ext2_t* ext2, ext2_ino_t ino)
{
#ifdef CHECK
    assert(ino != 0);
#endif

    return (ino - 1) % ext2->sb.s_inodes_per_group;
}

static int _write_inode_bitmap(
    const ext2_t* ext2,
    uint32_t group_index,
    const ext2_block_t* block)
{
    int ret = 0;
    uint32_t bitmap_size_bytes;

    bitmap_size_bytes = ext2->sb.s_inodes_per_group / 8;

    if (block->size != bitmap_size_bytes)
        ERAISE(-EINVAL);

    if (group_index > ext2->group_count)
        ERAISE(-EINVAL);

    ECHECK(
        _write_block(ext2, ext2->groups[group_index].bg_inode_bitmap, block));

done:
    return ret;
}

static int _get_ino(ext2_t* ext2, ext2_ino_t* ino)
{
    int ret = 0;
    uint32_t grpno;
    struct locals
    {
        ext2_block_t bitmap;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Clear the node number */
    *ino = 0;

    /* Use brute force search for a free inode number */
    for (grpno = 0; grpno < ext2->group_count; grpno++)
    {
        uint32_t lino;
        const uint8_t* p;

        /* Read the bitmap */
        ECHECK(ext2_read_inode_bitmap(ext2, grpno, &locals->bitmap));

        /* skip over full (0xff) bytes */
        p = myst_memcchr(locals->bitmap.data, 0xff, locals->bitmap.size);

        if (p)
            lino = (p - locals->bitmap.data) * 8;
        else
            lino = locals->bitmap.size * 8;

        /* Scan the bitmap, looking for free bit */
        for (; lino < locals->bitmap.size * 8; lino++)
        {
            if (!ext2_test_bit(locals->bitmap.data, locals->bitmap.size, lino))
            {
                _set_bit(locals->bitmap.data, locals->bitmap.size, lino);
                *ino = ext2_make_ino(ext2, grpno, lino);
                break;
            }
        }

        if (*ino)
            break;
    }

    /* If no free inode numbers */
    if (!*ino)
        ERAISE(-ENOSPC);

    /* Write the superblock */
    ext2->sb.s_free_inodes_count--;
    ERAISE(_write_super_block(ext2));

    /* Write the group */
    ext2->groups[grpno].bg_free_inodes_count--;
    ECHECK(_write_group(ext2, grpno));

    /* Write the bitmap */
    ECHECK(_write_inode_bitmap(ext2, grpno, &locals->bitmap));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _put_ino(ext2_t* ext2, ext2_ino_t ino)
{
    int ret = 0;
    uint32_t grpno;
    uint32_t lino;
    struct locals
    {
        ext2_block_t bitmap;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* get the group number from the inode number */
    if ((grpno = _ino_to_grpno(ext2, ino)) >= ext2->group_count)
        ERAISE(-EINVAL);

    /* read the inode bitmap for this group */
    ECHECK(ext2_read_inode_bitmap(ext2, grpno, &locals->bitmap));

    /* get the logical inode number from the inode number */
    if ((lino = _ino_to_lino(ext2, ino)) >= (locals->bitmap.size * 8))
    {
        ERAISE(-EINVAL);
    }

    /* clear the bitmap bit */
    _clear_bit(locals->bitmap.data, locals->bitmap.size, lino);

    /* update the global inode count and write the superblock */
    ext2->sb.s_free_inodes_count++;
    ERAISE(_write_super_block(ext2));

    /* update the group inode count and write the group */
    ext2->groups[grpno].bg_free_inodes_count++;
    ECHECK(_write_group(ext2, grpno));

    /* Write the bitmap */
    ECHECK(_write_inode_bitmap(ext2, grpno, &locals->bitmap));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _write_inode(
    const ext2_t* ext2,
    ext2_ino_t ino,
    const ext2_inode_t* inode)
{
    int ret = 0;
    uint32_t lino = _ino_to_lino(ext2, ino);
    uint32_t grpno = _ino_to_grpno(ext2, ino);
    const ext2_group_desc_t* group = &ext2->groups[grpno];
    uint32_t inode_size = ext2->sb.s_inode_size;
    uint64_t offset;

#ifdef CHECK
    /* Check the reverse mapping */
    {
        ext2_ino_t tmp;
        tmp = ext2_make_ino(ext2, grpno, lino);
        assert(tmp == ino);
    }
#endif

    offset = _blk_offset(group->bg_inode_table, ext2->block_size) +
             ((uint64_t)lino * (uint64_t)inode_size);

    /* Read the inode */
    if (_write(ext2->dev, offset, inode, inode_size) != inode_size)
        ERAISE(-ENOSPC);

    ret = 0;

done:
    return ret;
}

static int _load_file(
    ext2_t* ext2,
    myst_file_t* file,
    void** data_out,
    size_t* size_out)
{
    int ret = 0;
    struct stat st;
    char* block = NULL;
    const size_t block_size = 1024;
    void* data = NULL;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!(block = malloc(block_size)))
        ERAISE(-ENOMEM);

    ECHECK(ext2_fstat(&ext2->base, file, &st));

    if (!(data = malloc((size_t)(st.st_size))))
        ERAISE(-ENOMEM);

    /* handle symlinks shorter than 60 bytes up front */
    if (S_ISLNK(file->shared->inode.i_mode) && file->shared->inode.i_size < 60)
    {
        memcpy(data, file->shared->inode.i_block, file->shared->inode.i_size);
    }
    else
    {
        uint8_t* p = data;
        ssize_t n;

        while ((n = ext2_read(&ext2->base, file, block, block_size)) > 0)
        {
            memcpy(p, block, (size_t)n);
            p += n;
        }
    }

    *data_out = data;
    data = NULL;
    *size_out = (size_t)st.st_size;

done:

    if (block)
        free(block);

    if (data)
        free(data);

    return ret;
}

static int _load_file_by_path(
    ext2_t* ext2,
    const char* path,
    void** data_out,
    size_t* size_out)
{
    int ret = 0;
    myst_file_t* file = NULL;
    void* data = NULL;
    size_t size;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!path || !data_out || !size_out)
        ERAISE(-EINVAL);

    ECHECK(ext2_open(&ext2->base, path, O_RDONLY, 0000, NULL, &file));
    ECHECK(_load_file(ext2, file, &data, &size));

    *data_out = data;
    data = NULL;
    *size_out = size;

done:

    if (file)
        ext2_close(&ext2->base, file);

    if (data)
        free(data);

    return ret;
}

static int _load_file_by_inode(
    ext2_t* ext2,
    ext2_ino_t ino,
    const ext2_inode_t* inode,
    void** data,
    size_t* size)
{
    int ret = 0;
    struct locals
    {
        myst_file_t file;
        myst_file_shared_t file_shared;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Initialize the output */
    *data = NULL;
    *size = 0;

    /* load the contents of the file */
    {
        /* create a dummy file struct */
        memset(locals, 0, sizeof(struct locals));
        locals->file.shared = &locals->file_shared;
        locals->file_shared.magic = FILE_MAGIC;
        locals->file_shared.ino = ino;
        locals->file_shared.inode = *inode;
        locals->file_shared.offset = 0;
        locals->file_shared.access = O_RDONLY;
        locals->file_shared.open_flags = O_RDONLY;

        /* load the data */
        ECHECK(_load_file(ext2, &locals->file, data, size));
        _file_clear(&locals->file);
        _file_shared_clear(&locals->file_shared);
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static int _load_file_by_ino(
    ext2_t* ext2,
    ext2_ino_t ino,
    void** data,
    size_t* size)
{
    int ret = 0;
    struct locals
    {
        ext2_inode_t inode;
        myst_file_t file;
        myst_file_shared_t file_shared;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK((ext2_read_inode(ext2, ino, &locals->inode)));

    /* load the contents of the file */
    {
        /* create a dummy file struct */
        memset(&locals->file, 0, sizeof(locals->file));
        memset(&locals->file_shared, 0, sizeof(locals->file_shared));
        locals->file.shared = &locals->file_shared;
        locals->file_shared.magic = FILE_MAGIC;
        locals->file_shared.ino = ino;
        locals->file_shared.inode = locals->inode;
        locals->file_shared.offset = 0;
        locals->file_shared.access = O_RDONLY;
        locals->file_shared.open_flags = O_RDONLY;

        /* load the data */
        ECHECK(_load_file(ext2, &locals->file, data, size));
        _file_clear(&locals->file);
        _file_shared_clear(&locals->file_shared);
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static bool _streq(const char* s1, size_t n1, const char* s2, size_t n2)
{
    size_t n = _min_size(n1, n2);
    return n1 == n2 && memcmp(s1, s2, n) == 0;
}

static const ext2_dirent_t* _find_dirent(
    const char* name,
    const void* data,
    uint32_t size)
{
    const uint8_t* p = (uint8_t*)data;
    const uint8_t* end = (uint8_t*)data + size;
    size_t len = strlen(name);

    /* Make sure the fixed-length header portion is in range before accessing*/
    while (p + sizeof(ext2_dirent_t) - EXT2_FILENAME_MAX <= end)
    {
        const ext2_dirent_t* ent = (const ext2_dirent_t*)p;

        /* rec_len should not be 0 */
        if (!ent->rec_len)
        {
            assert(0);
            break;
        }
        /* the name string should be within the range */
        if ((uint8_t*)(ent->name) + ent->name_len > end)
        {
            assert(0);
            break;
        }

        if (_streq(ent->name, ent->name_len, name, len))
            return ent;

        p += ent->rec_len;
    }

    /* Not found */
    return NULL;
}

static int _load_dirent(
    ext2_t* ext2,
    ext2_ino_t dino,
    const char* name,
    ext2_dirent_t* ent)
{
    int ret = 0;
    void* data = NULL;
    size_t size;
    const ext2_dirent_t* p;

    ECHECK((_load_file_by_ino(ext2, dino, &data, &size)));

    if (!(p = _find_dirent(name, data, size)))
        ERAISE(-ENOENT);

    memcpy(ent, p, _dirent_size(p));

done:

    if (data)
        free(data);

    return ret;
}

typedef enum follow
{
    NOFOLLOW = 0,
    FOLLOW = 1,
} follow_t;

static int _path_to_ino_recursive(
    ext2_t* ext2,
    size_t* num_symlinks,
    const char* path,
    ext2_ino_t current_ino,
    follow_t follow,
    ext2_ino_t* dir_ino_out,
    ext2_ino_t* file_ino_out,
    char realpath[PATH_MAX],
    char target_out[PATH_MAX])
{
    int ret = 0;
    struct locals
    {
        char buf[PATH_MAX];
        char target[PATH_MAX];
        ext2_inode_t current_inode;
        ext2_dirent_t ent;
        ext2_ino_t ino;
    };
    struct locals* locals = NULL;
    myst_strarr_t toks = MYST_STRARR_INITIALIZER;
    char* p;
    char* save;
    size_t i;
    ext2_ino_t previous_ino = 0;
    void* data = NULL;
    size_t size;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (dir_ino_out)
        *dir_ino_out = 0;

    if (file_ino_out)
        *file_ino_out = 0;

    if (myst_strlcpy(locals->buf, path, sizeof(locals->buf)) >= PATH_MAX)
        ERAISE(-ENAMETOOLONG);

    if (path[0] == '/')
        current_ino = EXT2_ROOT_INO;

    /* split the path into components */
    for (p = strtok_r(locals->buf, "/", &save); p;
         p = strtok_r(NULL, "/", &save))
    {
        if (myst_strarr_append(&toks, p) != 0)
            ERAISE(-ENOMEM);
    }

    /* load each inode along the path until found */
    for (i = 0; i < toks.size; i++)
    {
        ECHECK(ext2_read_inode(ext2, current_ino, &locals->current_inode));
        if (!S_ISDIR(locals->current_inode.i_mode))
            ERAISE(-ENOTDIR);

        ECHECK(_load_dirent(ext2, current_ino, toks.data[i], &locals->ent));
        assert(locals->ent.inode != 0);
        locals->ino = locals->ent.inode;

        /* if this is a symbolic link */
        if (locals->ent.file_type == EXT2_FT_SYMLINK)
        {
            /* only check follow tag on final element */
            if (i + 1 != toks.size || follow == FOLLOW)
            {
                /* fail if too many levels of symlinks */
                if ((*num_symlinks)++ == MAXSYMLINKS)
                    ERAISE(-ELOOP);

                /* load the target from the symlink */
                ECHECK((_load_file_by_ino(ext2, locals->ino, &data, &size)));

                if (size >= PATH_MAX)
                    ERAISE(-ENAMETOOLONG);

                memcpy(locals->target, data, size);
                locals->target[size] = '\0';

                if (*locals->target == '/')
                {
                    if (target_out)
                    {
                        myst_strlcpy(target_out, locals->target, PATH_MAX);

                        // Copy over rest of unresolved tokens
                        if (i + 1 != toks.size)
                        {
                            for (size_t j = i + 1; j < toks.size; j++)
                            {
                                if (myst_strlcat(target_out, "/", PATH_MAX) >=
                                    PATH_MAX)
                                    ERAISE_QUIET(-ENAMETOOLONG);

                                if (myst_strlcat(
                                        target_out, toks.data[j], PATH_MAX) >=
                                    PATH_MAX)
                                    ERAISE_QUIET(-ENAMETOOLONG);
                            }
                        }
                        goto done;
                    }
                    else
                    {
                        *realpath = '\0';
                        current_ino = EXT2_ROOT_INO;
                    }
                }

                // Ignore self-loops.
                if (strcmp(path, locals->target) != 0)
                {
                    // Recursively resolve links.
                    ECHECK(_path_to_ino_recursive(
                        ext2,
                        num_symlinks,
                        locals->target,
                        current_ino,
                        FOLLOW,
                        &current_ino,
                        &locals->ino,
                        realpath,
                        target_out));
                }

                free(data);
                data = NULL;
            }
        }
        else
        {
            myst_strlcat(realpath, "/", PATH_MAX);
            myst_strlcat(realpath, toks.data[i], PATH_MAX);
        }

        previous_ino = current_ino;
        current_ino = locals->ino;
    }

    if (dir_ino_out)
        *dir_ino_out = previous_ino;

    if (file_ino_out)
        *file_ino_out = current_ino;

    ret = 0;

done:

    myst_strarr_release(&toks);

    if (locals)
        free(locals);

    if (data)
        free(data);

    return ret;
}

static int _path_to_ino_realpath(
    ext2_t* ext2,
    const char* path,
    follow_t follow,
    ext2_ino_t* dir_ino_out,
    ext2_ino_t* file_ino_out,
    char realpath[PATH_MAX],
    char target_out[PATH_MAX])
{
    int ret = 0;
    ext2_ino_t curr_ino = EXT2_ROOT_INO;
    ext2_ino_t dino;
    ext2_ino_t ino;
    size_t num_symlinks = 0;

    /* the path must be absolute */
    if (path[0] != '/')
        ERAISE(-EINVAL);

    *realpath = '\0';

    ECHECK(_path_to_ino_recursive(
        ext2,
        &num_symlinks,
        path,
        curr_ino,
        follow,
        &dino,
        &ino,
        realpath,
        target_out));

    if (dir_ino_out)
        *dir_ino_out = dino;

    if (file_ino_out)
        *file_ino_out = ino;

    ret = 0;

done:
    return ret;
}

static int _path_to_ino(
    ext2_t* ext2,
    const char* path,
    follow_t follow,
    ext2_ino_t* dir_ino_out,
    ext2_ino_t* file_ino_out)
{
    int ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_ino_realpath(
        ext2, path, follow, dir_ino_out, file_ino_out, locals->realpath, NULL));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _path_to_inode_realpath(
    ext2_t* ext2,
    const char* path,
    follow_t follow,
    ext2_ino_t* dir_ino_out,
    ext2_ino_t* file_ino_out,
    ext2_inode_t* dir_inode_out,
    ext2_inode_t* file_inode_out,
    char realpath[PATH_MAX],
    char target_out[PATH_MAX])
{
    int ret = 0;
    ext2_ino_t dir_ino;
    ext2_ino_t file_ino;

    if (dir_ino_out)
        *dir_ino_out = 0;

    if (dir_inode_out)
        memset(dir_inode_out, 0, sizeof(ext2_inode_t));

    if (file_ino_out)
        *file_ino_out = 0;

    if (file_inode_out)
        memset(file_inode_out, 0, sizeof(ext2_inode_t));

    /* Check parameters */
    if (!ext2 || !path)
        ERAISE(-EINVAL);

    /* Find the ino for this path */
    ECHECK(_path_to_ino_realpath(
        ext2, path, follow, &dir_ino, &file_ino, realpath, target_out));

    /* If a symlink was encountered, exit early */
    if (target_out && *target_out != '\0')
        goto done;

    /* Read the directory inode */
    if (dir_inode_out && dir_ino != 0)
        ECHECK(ext2_read_inode(ext2, dir_ino, dir_inode_out));

    /* Read the file inode */
    if (file_inode_out)
        ECHECK(ext2_read_inode(ext2, file_ino, file_inode_out));

    if (dir_ino_out)
        *dir_ino_out = dir_ino;

    if (file_ino_out)
        *file_ino_out = file_ino;

    ret = 0;

done:
    return ret;
}

static int _path_to_inode(
    ext2_t* ext2,
    const char* path,
    follow_t follow,
    ext2_ino_t* dir_ino_out,
    ext2_ino_t* file_ino_out,
    ext2_inode_t* dir_inode_out,
    ext2_inode_t* file_inode_out,
    char suffix[PATH_MAX],
    myst_fs_t** fs_out)
{
    int ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
        char target[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (suffix)
    {
        *suffix = '\0';
        *fs_out = NULL;
        *locals->target = '\0';
        ECHECK(_path_to_inode_realpath(
            ext2,
            path,
            follow,
            dir_ino_out,
            file_ino_out,
            dir_inode_out,
            file_inode_out,
            locals->realpath,
            locals->target));

        if (*locals->target != '\0' && ext2->resolve)
        {
            ECHECK((*ext2->resolve)(locals->target, suffix, fs_out));
        }
    }
    else
    {
        ECHECK(_path_to_inode_realpath(
            ext2,
            path,
            follow,
            dir_ino_out,
            file_ino_out,
            dir_inode_out,
            file_inode_out,
            locals->realpath,
            NULL));
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static int _count_dirents(
    const ext2_t* ext2,
    const void* data,
    uint32_t size,
    uint32_t* count)
{
    int ret = 0;
    const uint8_t* p = (uint8_t*)data;
    const uint8_t* end = (uint8_t*)data + size;

    /* Initialize the count */
    *count = 0;

    /* Must be divisiable by block size */
    if ((end - p) % ext2->block_size)
        ERAISE(-EINVAL);

    /* Make sure the fixed-length header portion is in range before accessing*/
    while (p + sizeof(ext2_dirent_t) - EXT2_FILENAME_MAX <= end)
    {
        const ext2_dirent_t* ent = (const ext2_dirent_t*)p;

        /* rec_len should not be 0 */
        if (!ent->rec_len)
        {
            assert(0);
            break;
        }

        if (ent->name_len)
        {
            (*count)++;
        }

        p += ent->rec_len;
    }
    /* last dirent should extend to the end of a block*/
    if (p != end)
        ERAISE(-EINVAL);

    ret = 0;

done:
    return ret;
}

/* return 0 if directory is empty (else raise -ENOTEMPTY) */
static int _inode_test_empty_directory(
    ext2_t* ext2,
    ext2_ino_t ino,
    ext2_inode_t* inode)
{
    int ret = 0;
    void* data = NULL;
    size_t size;
    uint32_t count;

    if (!S_ISDIR(inode->i_mode))
        ERAISE(-ENOTDIR);

    ECHECK(_load_file_by_inode(ext2, ino, inode, &data, &size));
    ECHECK(_count_dirents(ext2, data, size, &count));

    assert(count >= 2);

    if (count != 2)
        ERAISE(-ENOTEMPTY);

done:

    if (data)
        free(data);

    return ret;
}

static int _split_path(
    const char* path,
    char dirname[PATH_MAX],
    char basename[PATH_MAX])
{
    return myst_split_path(path, dirname, PATH_MAX, basename, PATH_MAX);
}

static size_t _inode_get_num_blocks(ext2_t* ext2, ext2_inode_t* inode)
{
    return (_inode_get_size(inode) + ext2->block_size - 1) / ext2->block_size;
}

static int _inode_get_blkno(
    ext2_t* ext2,
    ext2_inode_t* inode,
    size_t index,
    uint32_t* blkno_out)
{
    int ret = 0;
    size_t blknos_per_block = ext2->block_size / sizeof(uint32_t);
    size_t direct_max = EXT2_SINGLE_INDIRECT_BLOCK;
    size_t single_indirect_count = blknos_per_block;
    size_t single_indirect_max = direct_max + single_indirect_count;
    size_t double_indirect_count = single_indirect_count * blknos_per_block;
    size_t double_indirect_max = single_indirect_max + double_indirect_count;
    size_t triple_indirect_count = double_indirect_count * blknos_per_block;
    size_t triple_indirect_max = double_indirect_max + triple_indirect_count;
    ext2_block_t* block = NULL;

    if (!(block = malloc(sizeof(ext2_block_t))))
        ERAISE(-ENOMEM);

    *blkno_out = 0;

    /* handle direct block numbers */
    if (index < direct_max)
    {
        *blkno_out = inode->i_block[index];
        goto done;
    }

    /* handle single-indirect block numbers */
    if (index < single_indirect_max)
    {
        const size_t i = index - direct_max;
        const uint32_t blkno = inode->i_block[EXT2_SINGLE_INDIRECT_BLOCK];
        const uint32_t* data = (const uint32_t*)block->data;

        if (blkno == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, blkno, block));

        *blkno_out = data[i];
        goto done;
    }

    /* handle double-indirect block numbers */
    if (index < double_indirect_max)
    {
        const size_t n = index - single_indirect_max;
        const size_t i = n / blknos_per_block;
        const size_t j = n % blknos_per_block;
        uint32_t blkno;
        const uint32_t* data = (const uint32_t*)block->data;

        assert(n <= double_indirect_count);

        if ((blkno = inode->i_block[EXT2_DOUBLE_INDIRECT_BLOCK]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, blkno, block));

        if ((blkno = data[i]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, blkno, block));

        *blkno_out = data[j];
        goto done;
    }

    /* handle triple-indirect block numbers */
    if (index < triple_indirect_max)
    {
        const size_t n = index - double_indirect_max;
        const size_t i = n / (blknos_per_block * blknos_per_block);
        const size_t j = (n / blknos_per_block) % blknos_per_block;
        const size_t k = n % blknos_per_block;
        uint32_t blkno;
        const uint32_t* data = (const uint32_t*)block->data;

        assert(n <= triple_indirect_max);

        if ((blkno = inode->i_block[EXT2_TRIPLE_INDIRECT_BLOCK]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, blkno, block));

        if ((blkno = data[i]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, blkno, block));

        if ((blkno = data[j]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, blkno, block));

        *blkno_out = data[k];
        goto done;
    }

done:

    if (block)
        free(block);

    return ret;
}

static int _inode_add_blkno(
    ext2_t* ext2,
    ext2_ino_t ino,
    ext2_inode_t* inode,
    size_t index,
    uint32_t new_blkno)
{
    int ret = 0;
    size_t blknos_per_block = ext2->block_size / sizeof(uint32_t);
    size_t direct_max = EXT2_SINGLE_INDIRECT_BLOCK;
    size_t single_indirect_count = blknos_per_block;
    size_t single_indirect_max = direct_max + single_indirect_count;
    size_t double_indirect_count = single_indirect_count * blknos_per_block;
    size_t double_indirect_max = single_indirect_max + double_indirect_count;
    size_t triple_indirect_count = double_indirect_count * blknos_per_block;
    size_t triple_indirect_max = double_indirect_max + triple_indirect_count;
    struct locals
    {
        ext2_block_t iblock;
        ext2_block_t jblock;
        ext2_block_t kblock;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (new_blkno == 0)
        ERAISE(-EINVAL);

    /* handle direct block numbers */
    if (index < direct_max)
    {
        if (inode->i_block[index] != 0)
            ERAISE(-EEXIST);

        inode->i_block[index] = new_blkno;
        ECHECK(_write_inode(ext2, ino, inode));
        goto done;
    }

    /* handle single-indirect block numbers */
    if (index < single_indirect_max)
    {
        const size_t i = index - direct_max;
        uint32_t iblkno = inode->i_block[EXT2_SINGLE_INDIRECT_BLOCK];
        uint32_t* idata = (uint32_t*)locals->iblock.data;

        /* blkno-block does not exist yet */
        if (iblkno == 0)
        {
            /* assign a new block number */
            ECHECK(_get_blkno(ext2, &iblkno));

            /* update inode block array */
            inode->i_block[EXT2_SINGLE_INDIRECT_BLOCK] = iblkno;
            ECHECK(_write_inode(ext2, ino, inode));

            /* initialize, update and write the i-blkno-block */
            _init_block(&locals->iblock, ext2->block_size);
            idata[i] = new_blkno;
            ECHECK(_write_block(ext2, iblkno, &locals->iblock));
        }
        else
        {
            /* read the blkno-block */
            ECHECK(ext2_read_block(ext2, iblkno, &locals->iblock));

            /* if entry is already in use */
            if (idata[i] != 0)
                ERAISE(-EEXIST);

            /* update and write the i-blkno-block */
            idata[i] = new_blkno;
            ECHECK(_write_block(ext2, iblkno, &locals->iblock));
        }

        ret = 0;
        goto done;
    }

    /* handle double-indirect block numbers */
    if (index < double_indirect_max)
    {
        const size_t n = index - single_indirect_max;
        const size_t i = n / blknos_per_block;
        const size_t j = n % blknos_per_block;
        uint32_t iblkno = inode->i_block[EXT2_DOUBLE_INDIRECT_BLOCK];
        uint32_t jblkno = 0;
        uint32_t* idata = (uint32_t*)locals->iblock.data;
        uint32_t* jdata = (uint32_t*)locals->jblock.data;

        assert(n <= double_indirect_count);

        if (iblkno == 0)
        {
            /* assign a new i-block number */
            ECHECK(_get_blkno(ext2, &iblkno));

            /* assign a new j-block number */
            ECHECK(_get_blkno(ext2, &jblkno));

            /* update inode block array */
            inode->i_block[EXT2_DOUBLE_INDIRECT_BLOCK] = iblkno;
            ECHECK(_write_inode(ext2, ino, inode));

            /* write the i-blkno-block */
            _init_block(&locals->iblock, ext2->block_size);
            idata[i] = jblkno;
            ECHECK(_write_block(ext2, iblkno, &locals->iblock));

            /* write the j-blkno-block */
            _init_block(&locals->jblock, ext2->block_size);
            jdata[j] = new_blkno;
            ECHECK(_write_block(ext2, jblkno, &locals->jblock));
        }
        else /* iblkno != 0 */
        {
            ECHECK(ext2_read_block(ext2, iblkno, &locals->iblock));
            jblkno = idata[i];

            if (jblkno == 0)
            {
                /* assign a new j-block number */
                ECHECK(_get_blkno(ext2, &jblkno));

                /* write the i-blkno-block */
                idata[i] = jblkno;
                ECHECK(_write_block(ext2, iblkno, &locals->iblock));

                /* write the j-blkno-block */
                _init_block(&locals->jblock, ext2->block_size);
                jdata[j] = new_blkno;
                ECHECK(_write_block(ext2, jblkno, &locals->jblock));
            }
            else
            {
                /* read the j-blkno-block */
                ECHECK(ext2_read_block(ext2, jblkno, &locals->jblock));

                /* if entry is already in use */
                if (jdata[j] != 0)
                    ERAISE(-EEXIST);

                /* update and write the j-blkno-block */
                jdata[j] = new_blkno;
                ECHECK(_write_block(ext2, jblkno, &locals->jblock));
            }
        }

        ret = 0;
        goto done;
    }

    /* handle triple-indirect block numbers */
    if (index < triple_indirect_max)
    {
        const size_t n = index - double_indirect_max;
        const size_t i = n / (blknos_per_block * blknos_per_block);
        const size_t j = (n / blknos_per_block) % blknos_per_block;
        const size_t k = n % blknos_per_block;
        uint32_t iblkno = inode->i_block[EXT2_TRIPLE_INDIRECT_BLOCK];
        uint32_t jblkno = 0;
        uint32_t kblkno = 0;
        uint32_t* idata = (uint32_t*)locals->iblock.data;
        uint32_t* jdata = (uint32_t*)locals->jblock.data;
        uint32_t* kdata = (uint32_t*)locals->kblock.data;

        assert(n <= double_indirect_count);

        if (iblkno == 0)
        {
            /* assign a new i-block number */
            ECHECK(_get_blkno(ext2, &iblkno));

            /* assign a new j-block number */
            ECHECK(_get_blkno(ext2, &jblkno));

            /* assign a new k-block number */
            ECHECK(_get_blkno(ext2, &kblkno));

            /* update inode block array */
            inode->i_block[EXT2_TRIPLE_INDIRECT_BLOCK] = iblkno;
            ECHECK(_write_inode(ext2, ino, inode));

            /* write the i-blkno-block */
            _init_block(&locals->iblock, ext2->block_size);
            idata[i] = jblkno;
            ECHECK(_write_block(ext2, iblkno, &locals->iblock));

            /* write the j-blkno-block */
            _init_block(&locals->jblock, ext2->block_size);
            jdata[j] = kblkno;
            ECHECK(_write_block(ext2, jblkno, &locals->jblock));

            /* write the k-blkno-block */
            _init_block(&locals->kblock, ext2->block_size);
            kdata[k] = new_blkno;
            ECHECK(_write_block(ext2, kblkno, &locals->kblock));
        }
        else /* iblkno != 0 */
        {
            ECHECK(ext2_read_block(ext2, iblkno, &locals->iblock));
            jblkno = idata[i];

            if (jblkno == 0)
            {
                /* assign a new j-block number */
                ECHECK(_get_blkno(ext2, &jblkno));

                /* assign a new k-block number */
                ECHECK(_get_blkno(ext2, &kblkno));

                /* write the j-blkno-block */
                idata[i] = jblkno;
                ECHECK(_write_block(ext2, iblkno, &locals->iblock));

                /* write the j-blkno-block */
                _init_block(&locals->jblock, ext2->block_size);
                jdata[j] = kblkno;
                ECHECK(_write_block(ext2, jblkno, &locals->jblock));

                /* write the k-blkno-block */
                _init_block(&locals->kblock, ext2->block_size);
                kdata[k] = new_blkno;
                ECHECK(_write_block(ext2, kblkno, &locals->kblock));
            }
            else /* jblkno != 0 */
            {
                /* read the j-blkno-block */
                ECHECK(ext2_read_block(ext2, jblkno, &locals->jblock));
                kblkno = jdata[j];

                if (kblkno == 0)
                {
                    /* assign a new k-block number */
                    ECHECK(_get_blkno(ext2, &kblkno));

                    /* write the j-blkno-block */
                    jdata[j] = kblkno;
                    ECHECK(_write_block(ext2, jblkno, &locals->jblock));

                    /* write the k-blkno-block */
                    _init_block(&locals->kblock, ext2->block_size);
                    kdata[k] = new_blkno;
                    ECHECK(_write_block(ext2, kblkno, &locals->kblock));
                }
                else
                {
                    /* read the k-blkno-block */
                    ECHECK(ext2_read_block(ext2, kblkno, &locals->kblock));

                    /* if entry is already in use */
                    if (kdata[k] != 0)
                        ERAISE(-EEXIST);

                    /* update and write the k-blkno-block */
                    kdata[k] = new_blkno;
                    ECHECK(_write_block(ext2, kblkno, &locals->kblock));
                }
            }
        }

        ret = 0;
        goto done;
    }

done:

    if (locals)
        free(locals);

    return ret;
}

/* the caller is responsible for writing the inode */
static int _inode_put_blkno(
    ext2_t* ext2,
    ext2_ino_t ino,
    ext2_inode_t* inode,
    size_t index)
{
    int ret = 0;
    size_t blknos_per_block = ext2->block_size / sizeof(uint32_t);
    size_t direct_max = EXT2_SINGLE_INDIRECT_BLOCK;
    size_t single_indirect_count = blknos_per_block;
    size_t single_indirect_max = direct_max + single_indirect_count;
    size_t double_indirect_count = single_indirect_count * blknos_per_block;
    size_t double_indirect_max = single_indirect_max + double_indirect_count;
    size_t triple_indirect_count = double_indirect_count * blknos_per_block;
    size_t triple_indirect_max = double_indirect_max + triple_indirect_count;
    struct locals
    {
        ext2_block_t iblock;
        ext2_block_t jblock;
        ext2_block_t kblock;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* handle direct block numbers */
    if (index < direct_max)
    {
        uint32_t blkno = inode->i_block[index];

        if (blkno == 0)
            goto done;

        ECHECK(_put_blkno(ext2, blkno));
        inode->i_block[index] = 0;
        goto done;
    }

    /* handle single-indirect block numbers */
    if (index < single_indirect_max)
    {
        const size_t i = index - direct_max;
        const uint32_t iblkno = inode->i_block[EXT2_SINGLE_INDIRECT_BLOCK];
        uint32_t* idata = (uint32_t*)locals->iblock.data;
        uint32_t blkno;

        if (iblkno == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, iblkno, &locals->iblock));

        if ((blkno = idata[i]) == 0)
            goto done;

        ECHECK(_put_blkno(ext2, blkno));
        idata[i] = 0;

        if (_zero_filled_u32(idata, blknos_per_block))
        {
            ECHECK(_put_blkno(ext2, iblkno));
            inode->i_block[EXT2_SINGLE_INDIRECT_BLOCK] = 0;
        }
        else
        {
            ECHECK(_write_block(ext2, iblkno, &locals->iblock));
        }

        goto done;
    }

    /* handle double-indirect block numbers */
    if (index < double_indirect_max)
    {
        const size_t n = index - single_indirect_max;
        const size_t i = n / blknos_per_block;
        const size_t j = n % blknos_per_block;
        uint32_t iblkno = inode->i_block[EXT2_DOUBLE_INDIRECT_BLOCK];
        uint32_t jblkno;
        uint32_t* idata = (uint32_t*)locals->iblock.data;
        uint32_t* jdata = (uint32_t*)locals->jblock.data;
        uint32_t blkno;

        if (iblkno == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, iblkno, &locals->iblock));

        if ((jblkno = idata[i]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, jblkno, &locals->jblock));

        if ((blkno = jdata[j]) == 0)
            goto done;

        ECHECK(_put_blkno(ext2, blkno));
        jdata[j] = 0;

        if (_zero_filled_u32(jdata, blknos_per_block))
        {
            ECHECK(_put_blkno(ext2, jblkno));
            idata[i] = 0;

            if (_zero_filled_u32(idata, blknos_per_block))
            {
                ECHECK(_put_blkno(ext2, iblkno));
                inode->i_block[EXT2_DOUBLE_INDIRECT_BLOCK] = 0;
            }
            else
            {
                ECHECK(_write_block(ext2, iblkno, &locals->iblock));
            }
        }
        else
        {
            ECHECK(_write_block(ext2, jblkno, &locals->jblock));
        }

        goto done;
    }

    /* handle triple-indirect block numbers */
    if (index < triple_indirect_max)
    {
        const size_t n = index - double_indirect_max;
        const size_t i = n / (blknos_per_block * blknos_per_block);
        const size_t j = (n / blknos_per_block) % blknos_per_block;
        const size_t k = n % blknos_per_block;
        uint32_t iblkno = inode->i_block[EXT2_TRIPLE_INDIRECT_BLOCK];
        uint32_t jblkno;
        uint32_t kblkno;
        uint32_t* idata = (uint32_t*)locals->iblock.data;
        uint32_t* jdata = (uint32_t*)locals->jblock.data;
        uint32_t* kdata = (uint32_t*)locals->kblock.data;
        uint32_t blkno;

        if (iblkno == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, iblkno, &locals->iblock));

        if ((jblkno = idata[i]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, jblkno, &locals->jblock));

        if ((kblkno = jdata[j]) == 0)
            goto done;

        ECHECK(ext2_read_block(ext2, kblkno, &locals->kblock));

        if ((blkno = kdata[k]) == 0)
            goto done;

        ECHECK(_put_blkno(ext2, blkno));
        kdata[k] = 0;

        if (_zero_filled_u32(kdata, blknos_per_block))
        {
            ECHECK(_put_blkno(ext2, kblkno));
            jdata[i] = 0;

            if (_zero_filled_u32(jdata, blknos_per_block))
            {
                ECHECK(_put_blkno(ext2, jblkno));
                idata[i] = 0;

                if (_zero_filled_u32(idata, blknos_per_block))
                {
                    ECHECK(_put_blkno(ext2, iblkno));
                    inode->i_block[EXT2_TRIPLE_INDIRECT_BLOCK] = 0;
                }
                else
                {
                    ECHECK(_write_block(ext2, iblkno, &locals->iblock));
                }
            }
            else
            {
                ECHECK(_write_block(ext2, jblkno, &locals->jblock));
            }
        }
        else
        {
            ECHECK(_write_block(ext2, kblkno, &locals->kblock));
        }

        goto done;
    }

done:

    if (locals)
        free(locals);

    return ret;
}

#ifdef CHECKS
static int _check_dirents(const ext2_t* ext2, const void* data, uint32_t size)
{
    int ret = 0;
    const uint8_t* p = (uint8_t*)data;
    const uint8_t* end = (uint8_t*)data + size;

    /* Must be divisiable by block size */
    if ((end - p) % ext2->block_size)
        ERAISE(-EINVAL);

    /* Make sure the fixed-length header portion is in range before accessing*/
    while (p + sizeof(ext2_dirent_t) - EXT2_PATH_MAX <= end)
    {
        uint32_t n;
        const ext2_dirent_t* ent = (const ext2_dirent_t*)p;

        /* rec_len should not be 0 */
        if (!ent->rec_len)
        {
            assert(0);
            break;
        }

        n = sizeof(ext2_dirent_t) - EXT2_PATH_MAX + ent->name_len;
        n = _next_mult(n, 4);

        if (n != ent->rec_len)
        {
            uint32_t offset = ((char*)p - (char*)data) % ext2->block_size;
            uint32_t rem = ext2->block_size - offset;

            if (rem != ent->rec_len)
                ERAISE(-EINVAL);
        }

        p += ent->rec_len;
    }
    /* last dirent should extend to the end of a block*/
    if (p != end)
        ERAISE(-EINVAL);

done:
    return ret;
}
#endif

static int _ftruncate(ext2_t* ext2, myst_file_t* file, off_t length, bool isdir)
{
    int ret = 0;
    size_t file_size;
    size_t num_blocks;
    size_t first;
    struct locals
    {
        ext2_block_t block;
    };
    struct locals* locals = NULL;

    /* Fail if directory */
    if (!isdir && S_ISDIR(file->shared->inode.i_mode))
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* get the file size */
    file_size = _inode_get_size(&file->shared->inode);

    /* fail if length is out of range */
    if (length < 0)
        ERAISE(-EINVAL);

    if (length < file_size)
    {
        /* get the total number of blocks */
        num_blocks = _inode_get_num_blocks(ext2, &file->shared->inode);

        /* find the index of the first block number to delete */
        ECHECK(myst_round_up(length, ext2->block_size, &first));
        first /= ext2->block_size;

        /* release the selected block numbers */
        for (size_t i = first; i < num_blocks; i++)
            ECHECK(_inode_put_blkno(
                ext2, file->shared->ino, &file->shared->inode, i));

        /* Fill the last partial block with zeros */
        if (first > 0)
        {
            uint32_t blkno;

            /* get the block number of the last block */
            ECHECK(_inode_get_blkno(
                ext2, &file->shared->inode, first - 1, &blkno));

            if (blkno != 0)
            {
                size_t rlength;

                ECHECK(myst_round_up(length, ext2->block_size, &rlength));

                size_t size = rlength - length;
                size_t offset = ext2->block_size - size;

                if (size)
                {
                    ECHECK(ext2_read_block(ext2, blkno, &locals->block));
                    memset(locals->block.data + offset, 0, size);
                    ECHECK(_write_block(ext2, blkno, &locals->block));
                }
            }
        }

        _inode_set_size(&file->shared->inode, (size_t)length);
        _update_timestamps(&file->shared->inode, CHANGE | MODIFY);
        ECHECK(_write_inode(ext2, file->shared->ino, &file->shared->inode));
    }
    else if (length > file_size)
    {
        /* make file larger (with a file hole) */
        _inode_set_size(&file->shared->inode, length);
        _update_timestamps(&file->shared->inode, CHANGE | MODIFY);
        ECHECK(_write_inode(ext2, file->shared->ino, &file->shared->inode));
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static int _inode_write_data(
    ext2_t* ext2,
    ext2_ino_t ino,
    ext2_inode_t* inode,
    const void* data,
    size_t size)
{
    int ret = 0;
    struct locals* locals = NULL;
    const uint8_t* p = data;
    size_t r = size;
    bool isdir = S_ISDIR(inode->i_mode);
    struct locals
    {
        myst_file_t file;
        myst_file_shared_t file_shared;
        uint8_t buf[EXT2_MAX_BLOCK_SIZE];
    };

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    memset(&locals->file, 0, sizeof(myst_file_t));
    memset(&locals->file_shared, 0, sizeof(myst_file_shared_t));
    locals->file.shared = &locals->file_shared;
    locals->file_shared.magic = FILE_MAGIC;
    locals->file_shared.ino = ino;
    locals->file_shared.inode = *inode;
    locals->file_shared.offset = 0;
    locals->file_shared.access = O_WRONLY;
    locals->file_shared.open_flags = O_WRONLY;

    while (r)
    {
        size_t m = _min_size(r, ext2->block_size);
        ssize_t n;

        memcpy(locals->buf, p, m);
        ECHECK(n = ext2_write(&ext2->base, &locals->file, locals->buf, m));
        p += n;
        r -= n;
    }

    ECHECK(_ftruncate(ext2, &locals->file, size, isdir));

    memcpy(inode, &locals->file.shared->inode, sizeof(ext2_inode_t));
    _inode_set_size(inode, size);

done:

    if (locals)
    {
        _file_clear(&locals->file);
        _file_shared_clear(&locals->file_shared);
        free(locals);
    }

    return ret;
}

/* remove the directory entry with the given name */
static int _remove_dirent(
    ext2_t* ext2,
    ext2_ino_t ino,
    ext2_inode_t* inode,
    const char* filename,
    bool rename)
{
    int ret = 0;
    void* data = NULL;
    size_t size = 0;
    void* tdata = NULL;
    size_t tsize = 0;
    const ext2_dirent_t* ent;
    myst_buf_t buf = MYST_BUF_INITIALIZER;
    struct locals
    {
        ext2_inode_t tinode;
    };
    struct locals* locals = NULL;

    /* check parameters */
    if (!_ext2_valid(ext2) && !filename)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* load the directory file contents */
    ECHECK(_load_file_by_inode(ext2, ino, inode, &data, &size));

    /* find filename within this directory */
    if (!(ent = _find_dirent(filename, data, size)))
        ERAISE(-ENOENT);

    /* disallow removal if filename refers to a non-empty directory */
    if (ent->file_type == EXT2_FT_DIR)
    {
        uint32_t count;

        /* read the inode */
        ECHECK(ext2_read_inode(ext2, ent->inode, &locals->tinode));

        /* load the directory file contents */
        ECHECK(_load_file_by_inode(
            ext2, ent->inode, &locals->tinode, &tdata, &tsize));

        /* disallow removal if directory is non empty */
        ECHECK(_count_dirents(ext2, tdata, tsize, &count));

        /* expect two entries ("." and "..") */
        if (!rename && count != 2)
            ERAISE(-ENOTEMPTY);
    }

    /* convert from 'indexed' to 'linked list' directory format (if any) */
    {
        const size_t block_size = ext2->block_size;
        const size_t file_size = _inode_get_size(inode);
        const uint8_t* p = (const uint8_t*)data;
        const uint8_t* end = p + file_size;
        ssize_t prev = -1;

        if (myst_buf_reserve(&buf, file_size) < 0)
            ERAISE(-ENOMEM);

        /* Make sure the fixed-length header portion is in range before
         * accessing */
        while (p + sizeof(ext2_dirent_t) - EXT2_FILENAME_MAX <= end)
        {
            const ext2_dirent_t* e = (const ext2_dirent_t*)p;

            /* rec_len should not be 0 */
            if (!ent->rec_len)
            {
                assert(0);
                break;
            }
            /* add entry if not the one being removed */
            if (e != ent)
            {
                size_t recsz = _dirent_size(e);
                size_t rem = block_size - (buf.size % block_size);
                size_t curr;

                /* if there's room for another entry in this block */
                if (recsz <= rem)
                {
                    curr = buf.size;
                    if (myst_buf_append(&buf, e, recsz) < 0)
                        ERAISE(-ENOMEM);
                }
                else
                {
                    if (myst_buf_resize(&buf, buf.size + rem) < 0)
                        ERAISE(-ENOMEM);
                    curr = buf.size;
                    if (myst_buf_append(&buf, e, recsz) < 0)
                        ERAISE(-ENOMEM);

                    /* adjust the record length of the previous entry */
                    assert(prev >= 0);
                    ext2_dirent_t* prev_ent = (ext2_dirent_t*)(&buf.data[prev]);
                    prev_ent->rec_len += rem;
                }

                ext2_dirent_t* curr_ent = (ext2_dirent_t*)(&buf.data[curr]);
                curr_ent->rec_len = recsz;

                prev = curr;
            }

            p += e->rec_len;
        }

        /* pad with zeros and update previous entry */
        if (buf.size % block_size != 0)
        {
            size_t rem = block_size - (buf.size % block_size);

            if (rem)
                if (myst_buf_resize(&buf, buf.size + rem) < 0)
                    ERAISE(-ENOMEM);

            if (prev >= 0)
            {
                ext2_dirent_t* prev_ent = (ext2_dirent_t*)(&buf.data[prev]);

                if (rem != block_size)
                    prev_ent->rec_len += rem;
            }
        }

#ifdef CHECKS
        ECHECK(_check_dirents(ext2, buf.data, buf.size));
#endif
    }

    /* rewrite the directory, one block at a time */
    ECHECK(_inode_write_data(ext2, ino, inode, buf.data, buf.size));

    /* if child was a directory, then decrement the link count */
    if (ent->file_type == EXT2_FT_DIR)
        inode->i_links_count--;

    _update_timestamps(inode, CHANGE | MODIFY);

    ECHECK(_write_inode(ext2, ino, inode));

done:

    if (locals)
        free(locals);

    if (data)
        free(data);

    if (tdata)
        free(tdata);

    myst_buf_release(&buf);

    return ret;
}

static int _create_inode(
    ext2_t* ext2,
    uint32_t size,
    uint16_t mode,
    ext2_inode_t* inode,
    uint32_t* ino)
{
    int ret = 0;
    uid_t euid;
    gid_t egid;

    /* Check parameters */
    if (!_ext2_valid(ext2))
        ERAISE(-EINVAL);

    if (!inode || !ino)
        ERAISE(-EINVAL);

    euid = myst_syscall_geteuid();
    egid = myst_syscall_getegid();

    /* Initialize the inode */
    {
        const uint32_t t = (uint32_t)time(NULL);

        memset(inode, 0, sizeof(ext2_inode_t));

        /* Set the mode of the new file */
        inode->i_mode = mode;

        /* Set the uid and gid to root */
        inode->i_uid = euid & 0xFFFF;
        inode->i_osd2.linux2.i_uid_h = euid >> 16;
        inode->i_gid = egid & 0xFFFF;
        inode->i_osd2.linux2.i_gid_h = egid >> 16;

        /* Set the size of this file */
        _inode_set_size(inode, size);

        /* Set the access, creation, and mtime to the same value */
        inode->i_atime = t;
        inode->i_ctime = t;
        inode->i_mtime = t;

        /* Linux-specific value */
        inode->i_osd1 = 1;

        /* The number of links is initially 1 */
        inode->i_links_count = 1;

        /* Set the number of 512 byte blocks */
        inode->i_blocks = 0;
    }

    /* assign an inode number */
    ECHECK(_get_ino(ext2, ino));

    _update_timestamps(inode, ACCESS | CHANGE | MODIFY);

    /* write the inode */
    ECHECK(_write_inode(ext2, *ino, inode));

done:
    return ret;
}

static int _create_dir_inode_and_block(
    ext2_t* ext2,
    ext2_ino_t parent_ino,
    uint16_t mode,
    ext2_ino_t* ino)
{
    int ret = 0;
    uint32_t blkno;
    struct locals
    {
        ext2_inode_t inode;
        ext2_block_t block;
        ext2_dirent_t dot1;
        ext2_dirent_t dot2;
    };
    struct locals* locals = NULL;

    /* Check parameters */
    if (!_ext2_valid(ext2) || !parent_ino || !ino)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Initialize the inode */
    {
        uid_t uid = myst_syscall_geteuid();
        gid_t gid = myst_syscall_getegid();
        const uint32_t t = (uint32_t)time(NULL);

        memset(&locals->inode, 0, sizeof(ext2_inode_t));

        /* Set the mode of the new file */
        locals->inode.i_mode = (S_IFDIR | mode);

        /* Set the uid and gid to root */
        locals->inode.i_uid = uid & 0xFFFF;
        locals->inode.i_osd2.linux2.i_uid_h = uid >> 16;
        locals->inode.i_gid = gid & 0xFFFF;
        locals->inode.i_osd2.linux2.i_gid_h = gid >> 16;

        /* Set the size of this file */
        _inode_set_size(&locals->inode, ext2->block_size);

        /* Set the access, creation, and mtime to the same value */
        locals->inode.i_atime = t;
        locals->inode.i_ctime = t;
        locals->inode.i_mtime = t;

        /* Linux-specific value */
        locals->inode.i_osd1 = 1;

        /* The number of links is initially 2 */
        locals->inode.i_links_count = 2;

        /* Set the number of 512 byte blocks */
        locals->inode.i_blocks = ext2->block_size / 512;

        _update_timestamps(&locals->inode, ACCESS | CHANGE | MODIFY);
    }

    /* Assign an inode number */
    ECHECK(_get_ino(ext2, ino));

    /* Assign a block number */
    ECHECK(_get_blkno(ext2, &blkno));

    /* Create a block to hold the two directory entries */
    {
        ext2_dirent_t* ent;

        /* The "." directory */
        _dirent_init(&locals->dot1, *ino, EXT2_FT_DIR, ".");

        /* The ".." directory */
        _dirent_init(&locals->dot2, parent_ino, EXT2_FT_DIR, "..");

        /* Initialize the directory entries block */
        memset(&locals->block, 0, sizeof(ext2_block_t));
        memcpy(locals->block.data, &locals->dot1, locals->dot1.rec_len);
        memcpy(
            locals->block.data + locals->dot1.rec_len,
            &locals->dot2,
            locals->dot2.rec_len);
        locals->block.size = ext2->block_size;

        /* Adjust dot2.rec_len to point to end of block */
        ent = (ext2_dirent_t*)(locals->block.data + locals->dot1.rec_len);

        ent->rec_len +=
            ext2->block_size - (locals->dot1.rec_len + locals->dot2.rec_len);

        /* write the block */
        ECHECK(_write_block(ext2, blkno, &locals->block));

        /* add the block number to the inode and write inode */
        ECHECK(_inode_add_blkno(ext2, *ino, &locals->inode, 0, blkno));
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static int _add_dirent(
    ext2_t* ext2,
    ext2_ino_t ino,
    ext2_inode_t* inode,
    const char* filename,
    ext2_dirent_t* new_ent)
{
    int ret = 0;
    void* data = NULL;
    size_t size = 0;
    myst_buf_t buf = MYST_BUF_INITIALIZER;

    /* Load the directory file */
    ECHECK(_load_file_by_inode(ext2, ino, inode, &data, &size));

    /* If 'filename' already exists within this directory */
    if ((_find_dirent(filename, data, size)))
        ERAISE(-EEXIST);

    /* convert from 'indexed' to 'linked list' directory format (if any) */
    {
        const size_t block_size = ext2->block_size;
        const size_t file_size = _inode_get_size(inode);
        const uint8_t* p = (const uint8_t*)data;
        const uint8_t* end = p + file_size;
        ssize_t prev = -1;

        if (myst_buf_reserve(&buf, file_size) < 0)
            ERAISE(-ENOMEM);

        /* copy existing entries to buffer */
        /* Make sure the fixed-length header portion is in range before
         * accessing */
        while (p + sizeof(ext2_dirent_t) - EXT2_FILENAME_MAX <= end)
        {
            const ext2_dirent_t* e = (const ext2_dirent_t*)p;
            size_t recsz = _dirent_size(e);
            size_t rem = block_size - (buf.size % block_size);
            size_t curr;

            /* if there's room for another entry in this block */
            if (recsz <= rem)
            {
                curr = buf.size;
                if (myst_buf_append(&buf, e, recsz) < 0)
                    ERAISE(-ENOMEM);
            }
            else
            {
                if (myst_buf_resize(&buf, buf.size + rem) < 0)
                    ERAISE(-ENOMEM);
                curr = buf.size;
                if (myst_buf_append(&buf, e, recsz) < 0)
                    ERAISE(-ENOMEM);

                /* adjust the record length of the previous entry */
                assert(prev >= 0);
                ext2_dirent_t* prev_ent = (ext2_dirent_t*)(&buf.data[prev]);
                prev_ent->rec_len += rem;
            }

            ext2_dirent_t* curr_ent = (ext2_dirent_t*)(&buf.data[curr]);
            curr_ent->rec_len = recsz;

            prev = curr;

            p += e->rec_len;
        }

        /* add new entry to the buffer */
        {
            const ext2_dirent_t* e = (const ext2_dirent_t*)new_ent;
            size_t recsz = _dirent_size(e);
            size_t rem = block_size - (buf.size % block_size);
            size_t curr;

            /* if there's room for another entry in this block */
            if (recsz <= rem)
            {
                curr = buf.size;
                if (myst_buf_append(&buf, e, recsz) < 0)
                    ERAISE(-ENOMEM);
            }
            else
            {
                if (myst_buf_resize(&buf, buf.size + rem) < 0)
                    ERAISE(-ENOMEM);
                curr = buf.size;
                if (myst_buf_append(&buf, e, recsz) < 0)
                    ERAISE(-ENOMEM);

                /* adjust the record length of the previous entry */
                assert(prev >= 0);
                ext2_dirent_t* prev_ent = (ext2_dirent_t*)(&buf.data[prev]);
                prev_ent->rec_len += rem;
            }

            ext2_dirent_t* curr_ent = (ext2_dirent_t*)(&buf.data[curr]);
            curr_ent->rec_len = recsz;

            prev = curr;
        }

        /* pad the buffer with zeros and update previous entry */
        if (buf.size % block_size != 0)
        {
            size_t rem = block_size - (buf.size % block_size);

            if (rem)
                if (myst_buf_resize(&buf, buf.size + rem) < 0)
                    ERAISE(-ENOMEM);

            if (prev >= 0)
            {
                ext2_dirent_t* prev_ent = (ext2_dirent_t*)(&buf.data[prev]);

                if (rem != block_size)
                    prev_ent->rec_len += rem;
            }
        }

#ifdef CHECKS
        ECHECK(_check_dirents(ext2, buf.data, buf.size));
#endif
    }

#ifdef CHECKS
    /* count directory entries before and after */
    {
        uint32_t count;
        uint32_t new_count;

        ECHECK(_count_dirents(ext2, data, size, &count));
        ECHECK(_count_dirents(ext2, buf.data, buf.size, &new_count));

        if (count + 1 != new_count)
            ERAISE(-EINVAL);
    }
    assert(_find_dirent(filename, buf.data, buf.size) != NULL);
#endif

    /* rewrite the directory, one block at a time */
    ECHECK(_inode_write_data(ext2, ino, inode, buf.data, buf.size));

    /* update the number of links if new entry is a directory */
    if (new_ent->file_type == EXT2_FT_DIR)
        inode->i_links_count++;

    _update_timestamps(inode, CHANGE | MODIFY);

    ECHECK(_write_inode(ext2, ino, inode));

done:

    if (data)
        free(data);

    myst_buf_release(&buf);

    return ret;
}

static int _inode_free(ext2_t* ext2, ext2_ino_t ino, ext2_inode_t* inode)
{
    int ret = 0;

    assert(inode->i_links_count == 1);

    size_t num_blocks = _inode_get_num_blocks(ext2, inode);

    if (S_ISLNK(inode->i_mode) && inode->i_size < 60)
        num_blocks = 0;

    for (size_t i = 0; i < num_blocks; i++)
    {
        ECHECK(_inode_put_blkno(ext2, ino, inode, i));
    }

    /* return the inode to the free list */
    ECHECK(_put_ino(ext2, ino));

done:
    return ret;
}

static int _inode_unlink(ext2_t* ext2, ext2_ino_t ino, ext2_inode_t* inode)
{
    int ret = 0;

    assert(inode->i_links_count >= 1);

    /* if this is the final link */
    if (inode->i_links_count == 1)
    {
        assert(_valid_ino(ext2, ino));

        /* if the inode is open */
        if (ext2->inode_refs[ino - 1].nopens > 0)
        {
            /* defer the inode free until close() */
            ext2->inode_refs[ino - 1].free = 1;
        }
        else
        {
            /* free the inode now */
            ECHECK(_inode_free(ext2, ino, inode));
            ext2->inode_refs[ino - 1].free = 0;
        }
    }
    else
    {
        /* decrement the link count and write the inode */
        inode->i_links_count--;
        _update_timestamps(inode, CHANGE);
        ECHECK(_write_inode(ext2, ino, inode));
    }

done:
    return ret;
}

/* ATTN: remove this when possible */
int ext2_lsr(ext2_t* ext2, const char* root, myst_strarr_t* paths)
{
    int ret = 0;
    ext2_dir_t* dir = NULL;
    struct dirent* ent;
    myst_strarr_t dirs = MYST_STRARR_INITIALIZER;
    int r;
    struct locals
    {
        char path[PATH_MAX];
    };
    struct locals* locals = NULL;

    /* Check parameters */
    if (!ext2 || !root || !paths)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Open the directory */
    ECHECK(ext2_opendir(&ext2->base, root, &dir));

    /* For each entry */
    while ((r = ext2_readdir(&ext2->base, dir, &ent)) == 1)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        myst_strlcpy(locals->path, root, sizeof(locals->path));

        if (strcmp(root, "/") != 0)
            myst_strlcat(locals->path, "/", sizeof(locals->path));

        myst_strlcat(locals->path, ent->d_name, sizeof(locals->path));

        /* Append to paths[] array */
        ECHECK(myst_strarr_append(paths, locals->path));

        /* Append to dirs[] array */
        if (ent->d_type == DT_DIR)
            ECHECK(myst_strarr_append(&dirs, locals->path));
    }

    if (r < 0)
        ERAISE(r);

    /* Recurse into child directories */
    for (uint64_t i = 0; i < dirs.size; i++)
    {
        ECHECK(ext2_lsr(ext2, dirs.data[i], paths));
    }

done:

    if (locals)
        free(locals);

    /* Close the directory */
    if (dir)
        ext2_closedir(&ext2->base, dir);

    myst_strarr_release(&dirs);

    if (ret != 0)
    {
        myst_strarr_release(paths);
        memset(paths, 0, sizeof(myst_strarr_t));
    }

    return ret;
}

int ext2_check(const ext2_t* ext2)
{
    int ret = 0;
    struct locals
    {
        ext2_block_t bitmap;
        ext2_inode_t inode;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check the block bitmaps */
    {
        uint32_t i;
        uint32_t n = 0;
        uint32_t nused = 0;
        uint32_t nfree = 0;

        for (i = 0; i < ext2->group_count; i++)
        {
            nfree += ext2->groups[i].bg_free_blocks_count;

            ECHECK(ext2_read_block_bitmap(ext2, i, &locals->bitmap));
            nused +=
                ext2_count_bits_n(locals->bitmap.data, locals->bitmap.size);
            n += locals->bitmap.size * 8;
        }

        if (ext2->sb.s_free_blocks_count != nfree)
        {
            printf(
                "s_free_blocks_count{%u}, nfree{%u}\n",
                ext2->sb.s_free_blocks_count,
                nfree);
            ERAISE(-EINVAL);
        }

        if (ext2->sb.s_free_blocks_count != n - nused)
            ERAISE(-EINVAL);
    }

    /* Check the inode bitmaps */
    {
        uint32_t i;
        uint32_t n = 0;
        uint32_t nused = 0;
        uint32_t nfree = 0;

        /* Check the bitmaps for the inodes */
        for (i = 0; i < ext2->group_count; i++)
        {
            nfree += ext2->groups[i].bg_free_inodes_count;

            ECHECK(ext2_read_inode_bitmap(ext2, i, &locals->bitmap));
            nused +=
                ext2_count_bits_n(locals->bitmap.data, locals->bitmap.size);
            n += locals->bitmap.size * 8;
        }

        if (ext2->sb.s_free_inodes_count != n - nused)
            ERAISE(-EINVAL);

        if (ext2->sb.s_free_inodes_count != nfree)
            ERAISE(-EINVAL);
    }

    /* Check the inodes */
    {
        uint32_t grpno;
        uint32_t nbits = 0;
        uint32_t mbits = 0;

        /* Check the inode tables */
        for (grpno = 0; grpno < ext2->group_count; grpno++)
        {
            uint32_t lino;

            /* Get inode bitmap for this group */
            ECHECK(ext2_read_inode_bitmap(ext2, grpno, &locals->bitmap));

            nbits +=
                ext2_count_bits_n(locals->bitmap.data, locals->bitmap.size);

            /* For each bit set in the bit map */
            for (lino = 0; lino < ext2->sb.s_inodes_per_group; lino++)
            {
                ext2_ino_t ino;

                if (!ext2_test_bit(
                        locals->bitmap.data, locals->bitmap.size, lino))
                    continue;

                mbits++;

                if ((lino + 1) < EXT2_FIRST_INO && (lino + 1) != EXT2_ROOT_INO)
                    continue;

                ino = ext2_make_ino(ext2, grpno, lino);

                ECHECK(ext2_read_inode(ext2, ino, &locals->inode));

                /* Mode can never be zero */
                if (locals->inode.i_mode == 0)
                    ERAISE(-EINVAL);
            }
        }

        /* The number of bits in bitmap must match number of active inodes */
        if (nbits != mbits)
            ERAISE(-EINVAL);
    }

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_read_block(const ext2_t* ext2, uint32_t blkno, ext2_block_t* block)
{
    int ret = 0;

    /* Check for null parameters */
    if (!_ext2_valid(ext2) || !block)
        ERAISE(-EINVAL);

    /* Is block size too big for buffer? */
    if (ext2->block_size > sizeof(block->data))
        ERAISE(-EOVERFLOW);

    /* Set the size of the block */
    block->size = ext2->block_size;

    /* Read the block */
    if (_read(
            ext2->dev,
            _blk_offset(blkno, ext2->block_size),
            block->data,
            block->size) != block->size)
    {
        ERAISE(-EIO);
    }

    ret = 0;

done:

    return ret;
}

int ext2_read_inode(const ext2_t* ext2, ext2_ino_t ino, ext2_inode_t* inode)
{
    int ret = 0;
    uint32_t lino = _ino_to_lino(ext2, ino);
    uint32_t grpno = _ino_to_grpno(ext2, ino);
    const ext2_group_desc_t* group = &ext2->groups[grpno];
    uint32_t inode_size = ext2->sb.s_inode_size;
    uint64_t offset;

    if (ino == 0)
        ERAISE(-EINVAL);

    /* Check the reverse mapping */
    {
        ext2_ino_t tmp;
        tmp = ext2_make_ino(ext2, grpno, lino);
        assert(tmp == ino);
    }

    offset = _blk_offset(group->bg_inode_table, ext2->block_size) +
             ((uint64_t)lino * (uint64_t)inode_size);

    /* Read the inode */
    if (_read(ext2->dev, offset, inode, inode_size) != inode_size)
        ERAISE(-EIO);

done:
    return ret;
}

int ext2_read_block_bitmap(
    const ext2_t* ext2,
    uint32_t group_index,
    ext2_block_t* block)
{
    int ret = 0;
    uint32_t bitmap_size_bytes;

    if (!_ext2_valid(ext2) || !block)
        ERAISE(-EINVAL);

    memset(block, 0, sizeof(ext2_block_t));

    bitmap_size_bytes = ext2->sb.s_blocks_per_group / 8;

    if (group_index > ext2->group_count)
        ERAISE(-EINVAL);

    ECHECK(ext2_read_block(
        ext2, ext2->groups[group_index].bg_block_bitmap, block));

    if (block->size > bitmap_size_bytes)
        block->size = bitmap_size_bytes;

done:
    return ret;
}

int ext2_read_inode_bitmap(
    const ext2_t* ext2,
    uint32_t group_index,
    ext2_block_t* block)
{
    int ret = 0;
    uint32_t bitmap_size_bytes;

    if (!_ext2_valid(ext2) || !block)
        ERAISE(-EINVAL);

    memset(block, 0, sizeof(ext2_block_t));

    bitmap_size_bytes = ext2->sb.s_inodes_per_group / 8;

    if (group_index > ext2->group_count)
        ERAISE(-EINVAL);

    ECHECK(ext2_read_block(
        ext2, ext2->groups[group_index].bg_inode_bitmap, block));

    if (block->size > bitmap_size_bytes)
        block->size = bitmap_size_bytes;

done:
    return ret;
}

static int _stat(
    ext2_t* ext2,
    ext2_ino_t* ino,
    ext2_inode_t* inode,
    struct stat* statbuf)
{
    int64_t ret = 0;
    struct locals
    {
        myst_file_t file;
        myst_file_shared_t file_shared;
    };
    struct locals* locals = NULL;

    if (!_ext2_valid(ext2) || !ino || !inode || !statbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* call ext2_fstat() */
    {
        memset(&locals->file, 0, sizeof(locals->file));
        memset(&locals->file_shared, 0, sizeof(locals->file_shared));
        locals->file.shared = &locals->file_shared;
        locals->file_shared.magic = FILE_MAGIC;
        locals->file_shared.ino = *ino;
        locals->file_shared.inode = *inode;
        locals->file_shared.offset = 0;
        locals->file_shared.access = O_RDONLY;
        locals->file_shared.open_flags = O_RDONLY;

        ECHECK(ext2_fstat(&ext2->base, &locals->file, statbuf));
        _file_clear(&locals->file);
    }

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_open(
    myst_fs_t* fs,
    const char* path,
    int flags,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    myst_file_t* file = NULL;
    myst_file_shared_t* file_shared = NULL;
    ext2_ino_t ino;
    int r;
    follow_t follow = FOLLOW;
    void* dir_data = NULL;
    size_t dir_size = 0;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        ext2_inode_t inode;
        ext2_dirent_t ent;
        char dirname[PATH_MAX];
        char filename[PATH_MAX];
        char suffix[PATH_MAX];
        char buf[PATH_MAX];
        ext2_inode_t dinode;
    };
    struct locals* locals = NULL;

    if (file_out)
        *file_out = NULL;

    /* reject null parameters */
    if (!ext2 || !path || !file_out)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* handle O_NOFOLLOW flag (applies to final component of path) */
    if ((flags & O_NOFOLLOW))
        follow = NOFOLLOW;

    r = _path_to_inode(
        ext2,
        path,
        follow,
        NULL,
        &ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs);

    if (tfs)
    {
        /* delegate open operation to target filesystem */
        ECHECK((*tfs->fs_open)(
            tfs, locals->suffix, flags, mode, fs_out, file_out));
        goto done;
    }
    else if (fs_out)
    {
        /* i.e path was fully resolved
        the file resides in the current fs */
        if (ext2->wrapper_fs)
            *fs_out = ext2->wrapper_fs;
        else
            *fs_out = fs;
    }

    /* find the inode for this file (if it exists) */
    if (r < 0)
    {
        ext2_ino_t dino;

        if (r != -ENOENT)
            ERAISE(r);

        if (!(flags & O_CREAT))
            ERAISE(-ENOENT);

        if ((flags & O_DIRECTORY))
            ERAISE(-ENOENT);

        /* split the path into directory and filename components */
        ECHECK(_split_path(path, locals->dirname, locals->filename));

        /* load the directory inode, symbolic link in the directory part of the
         * path should always be followed */
        ECHECK(_path_to_ino(ext2, locals->dirname, FOLLOW, NULL, &dino));
        ECHECK(ext2_read_inode(ext2, dino, &locals->dinode));

        /* create a new inode */
        ECHECK(_create_inode(ext2, 0, (S_IFREG | mode), &locals->inode, &ino));

        /* create new entry for this file in the directory inode */
        _dirent_init(&locals->ent, ino, EXT2_FT_REG_FILE, locals->filename);
        ECHECK(_add_dirent(
            ext2, dino, &locals->dinode, locals->filename, &locals->ent));
    }
    /* If file already exists, check whether both O_CREAT and O_EXCL were passed
     */
    else
    {
        if ((flags & O_CREAT) && (flags & O_EXCL))
            ERAISE(-EEXIST);
    }

    if (S_ISLNK(locals->inode.i_mode) && (flags & O_NOFOLLOW) &&
        !(flags & O_PATH))
        ERAISE(-ELOOP);

    /* fail if not a directory */
    if ((flags & O_DIRECTORY) && !S_ISDIR(locals->inode.i_mode))
    {
        ERAISE(-ENOTDIR);
    }

    /* bail out as this fs doesn't support O_TMPFILE (yet) */
    if ((flags & O_TMPFILE) && ((flags & O_RDWR) || (flags & O_WRONLY)) &&
        S_ISDIR(locals->inode.i_mode))
    {
        ERAISE(-EISDIR);
    }

    /* Allocate and initialize the file object */
    {
        if (!(file = (myst_file_t*)calloc(1, sizeof(myst_file_t))))
            ERAISE(-ENOMEM);

        if (!(file_shared =
                  (myst_file_shared_t*)calloc(1, sizeof(myst_file_shared_t))))
            ERAISE(-ENOMEM);

        file->shared = file_shared;
        file->shared->magic = FILE_MAGIC;
        file->shared->ino = ino;
        file->shared->inode = locals->inode;
        file->shared->offset = 0;
        file->shared->open_flags = flags;
        file->shared->access = (flags & O_PATH)
                                   ? O_PATH
                                   : (flags & (O_RDONLY | O_RDWR | O_WRONLY));
        file->shared->operating = (flags & (O_APPEND | O_NONBLOCK));
        file->shared->use_count = 1;
    }

    /* truncate the file if requested and if not zero-sized */
    if ((flags & O_TRUNC) && _inode_get_size(&locals->inode) != 0)
    {
        ECHECK(ext2_ftruncate(&ext2->base, file, 0));
    }

    /* if it is a directory, then open directory */
    if ((flags & O_DIRECTORY))
    {
        /* load the directory blocks into memory */
        ECHECK((_load_file_by_path(ext2, path, &dir_data, &dir_size)));

        file->shared->dir.data = dir_data;
        file->shared->dir.size = dir_size;
        file->shared->dir.next = file->shared->dir.data;
        dir_data = NULL;
    }

    /* Get the realpath of this file */
    {
        ECHECK(_path_to_ino_realpath(
            ext2, path, follow, NULL, NULL, locals->buf, NULL));
        myst_strlcpy(
            file->shared->realpath,
            locals->buf,
            sizeof(file->shared->realpath));
    }

    /* Increment the reference count for this inode number */
    _inode_ref(ext2, file->shared->ino);

    *file_out = file;
    file = NULL;
    file_shared = NULL;

done:

    if (locals)
        free(locals);

    if (file)
        _file_free(file);

    if (file_shared)
        _file_shared_free(file_shared);

    if (dir_data)
        free(dir_data);

    return ret;
}

int64_t ext2_read(myst_fs_t* fs, myst_file_t* file, void* data, uint64_t size)
{
    int64_t ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    uint32_t first;
    uint32_t i;
    uint64_t r;
    uint8_t* end = (uint8_t*)data;
    size_t num_blocks;
    bool eof = false;
    ext2_block_t* block = NULL;

    if (!(block = malloc(sizeof(ext2_block_t))))
        ERAISE(-ENOMEM);

    /* Check parameters */
    if (!_ext2_valid(ext2) || !_file_valid(file) || !data)
        ERAISE(-EINVAL);

    /* fail if file has been opened for write only */
    if (file->shared->access == O_WRONLY || file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* refresh the inode */
    ECHECK((ext2_read_inode(ext2, file->shared->ino, &file->shared->inode)));

    /* If offset is beyond end of file, return 0 */
    if (file->shared->offset >= _inode_get_size(&file->shared->inode))
        goto done;

    /* The index of the first block to read */
    first = file->shared->offset / ext2->block_size;

    /* The number of bytes r to be read */
    r = size;

    num_blocks = _inode_get_num_blocks(ext2, &file->shared->inode);

    /* Read the data block-by-block */
    for (i = first; i < num_blocks && r > 0 && !eof; i++)
    {
        uint32_t offset;
        uint32_t blkno;

        ECHECK(_inode_get_blkno(ext2, &file->shared->inode, i, &blkno));

        /* handle holes */
        if (blkno == 0)
            _init_block(block, ext2->block_size);
        else
            ECHECK(ext2_read_block(ext2, blkno, block));

        /* The offset of the data within this block */
        offset = file->shared->offset % ext2->block_size;

        /* Copy data to caller's buffer */
        {
            size_t n = _min_size(block->size - offset, r);

            /* reduce n to bytes remaining in the file */
            {
                uint64_t t = _inode_get_size(&file->shared->inode) -
                             file->shared->offset;

                if (t < n)
                {
                    n = t;
                    eof = true;
                }
            }

            /* Copy data to user buffer */
            memcpy(end, block->data + offset, n);
            r -= n;
            end += n;
            file->shared->offset += n;
        }
    }

    /* ATTN.TIMESTAMPS */

    /* Calculate number of bytes read */
    ret = size - r;

done:

    if (block)
        free(block);

    return ret;
}

int64_t ext2_write(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* data,
    uint64_t size)
{
    int64_t ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    uint32_t first; /* the first block to be written */
    uint64_t r;     /* remaining bytes to be written */
    uint8_t* p = (uint8_t*)data;
    uint32_t blkno = 0;
    size_t file_size;
    struct locals
    {
        ext2_block_t block;
    };
    struct locals* locals = NULL;

    /* check parameters */
    if (!_ext2_valid(ext2) || !_file_valid(file) || (!data && size))
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* check that file has been opened for write */
    if (file->shared->access == O_RDONLY || file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* succeed if writing zero bytes */
    if (size == 0)
        goto done;

    /* refresh inode */
    ECHECK((ext2_read_inode(ext2, file->shared->ino, &file->shared->inode)));

    /* save the file size */
    file_size = _inode_get_size(&file->shared->inode);

    /* append always writes to the end of the file */
    if ((file->shared->operating & O_APPEND))
        file->shared->offset = file_size;

    /* get the index of the first block to written */
    first = file->shared->offset / ext2->block_size;

    /* calculate the number of remaining bytes to be written */
    r = size;

    /* for each file data block to be written */
    for (size_t i = first; r > 0; i++)
    {
        uint32_t block_offset;
        bool found_blkno = false;

        /* get the block number for the i-th data block */
        ECHECK(_inode_get_blkno(ext2, &file->shared->inode, i, &blkno));

        /* if the block number is zero, create a new block */
        if (blkno == 0)
        {
            ECHECK(_get_blkno(ext2, &blkno));
            _init_block(&locals->block, ext2->block_size);
        }
        else
        {
            /* read the block into memory */
            ECHECK(ext2_read_block(ext2, blkno, &locals->block));
            found_blkno = true;
        }

        /* calculate the offset of the data within this block */
        block_offset = file->shared->offset % ext2->block_size;

        /* write to the current block */
        {
            size_t n;

            /* calculate bytes to write */
            n = _min_size(r, ext2->block_size - block_offset);

            /* copy buffer bytes onto block */
            memcpy(locals->block.data + block_offset, p, n);

            /* write the block */
            ECHECK(_write_block(ext2, blkno, &locals->block));

            /* add the block number to the inode */
            if (!found_blkno)
            {
                ECHECK(_inode_add_blkno(
                    ext2, file->shared->ino, &file->shared->inode, i, blkno));
            }

            /* set to zero to prevent it from being released below */
            blkno = 0;

            /* advance the file offset */
            file->shared->offset += n;

            r -= n;
            p += n;
        }
    }

    /* update the inode size */
    if (file->shared->offset > file_size)
        _inode_set_size(
            &file->shared->inode, _max_size(file->shared->offset, file_size));

    _update_timestamps(&file->shared->inode, CHANGE | MODIFY);

    /* flush the inode to disk */
    ECHECK(_write_inode(ext2, file->shared->ino, &file->shared->inode));

    /* calculate the number of bytes written */
    ret = size - r;

done:

    if (blkno != 0)
        _put_blkno(ext2, blkno);

    if (locals)
        free(locals);

    return ret;
}

off_t ext2_lseek(myst_fs_t* fs, myst_file_t* file, off_t offset, int whence)
{
    off_t ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    off_t new_offset = 0;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    switch (whence)
    {
        case SEEK_SET:
        {
            new_offset = offset;
            break;
        }
        case SEEK_CUR:
        {
            new_offset = (off_t)file->shared->offset + offset;
            break;
        }
        case SEEK_END:
        {
            new_offset = _inode_get_size(&file->shared->inode) + offset;
            break;
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

    /* EINVAL if the resulting file offset would be negative */
    if (new_offset < 0)
        ERAISE(-EINVAL);

    file->shared->offset = (uint64_t)new_offset;

    ret = new_offset;

done:

    return ret;
}

int ext2_close(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    /* check parameters */
    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    /* retreive ptr to file object shared between dups */
    myst_file_shared_t* shared = file->shared;

    /* release the file object specific to a file descriptor */
    _file_free(file);

    if (--shared->use_count == 0)
    {
        /* if a directory, then release the directory memory contents */
        if (shared->dir.data)
            free(shared->dir.data);

        /* ATTN:TIMESTAMPS */

        /* Decrement the inode reference count */
        if (_inode_unref(ext2, shared->ino) == 0)
        {
            /* If unlink() was called while this file was open */
            if (ext2->inode_refs[shared->ino - 1].free)
            {
                /* Refresh the inode */
                ext2_inode_t inode;
                ECHECK((ext2_read_inode(ext2, shared->ino, &inode)));

                /* Free the inode */
                ECHECK(_inode_free(ext2, shared->ino, &inode));
                ext2->inode_refs[shared->ino - 1].free = 0;
            }
        }

        /* release the shared file object */
        _file_shared_free(shared);
    }

done:
    return ret;
}

int ext2_access(myst_fs_t* fs, const char* pathname, int mode)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    myst_fs_t* tfs;
    struct locals
    {
        char suffix[PATH_MAX];
        ext2_inode_t inode;
    };
    struct locals* locals = NULL;

    /* ATTN: dereference symbolic links */

    if (!_ext2_valid(ext2) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (mode != F_OK && !(mode & (R_OK | W_OK | X_OK)))
        ERAISE(-EINVAL);

    /* fetch the inode */
    ECHECK(_path_to_inode(
        ext2,
        pathname,
        FOLLOW,
        NULL,
        NULL,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((ret = tfs->fs_access(tfs, locals->suffix, mode)));
        goto done;
    }

    if (mode == F_OK)
        goto done;

    if ((mode & R_OK) && !(locals->inode.i_mode & S_IRUSR))
        ERAISE(-EACCES);

    if ((mode & W_OK) && !(locals->inode.i_mode & S_IWUSR))
        ERAISE(-EACCES);

    if ((mode & X_OK) && !(locals->inode.i_mode & S_IXUSR))
        ERAISE(-EACCES);

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_link(
    myst_fs_t* fs,
    const char* oldpath,
    const char* newpath,
    int flags)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    ext2_ino_t dino;
    ext2_ino_t ino;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        char dirname[PATH_MAX];
        char filename[PATH_MAX];
        char suffix[PATH_MAX];
        ext2_inode_t inode;
        ext2_inode_t dinode;
        ext2_dirent_t ent;
    };
    struct locals* locals = NULL;

    /* check parameters */
    if (!_ext2_valid(ext2) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    follow_t oldpath_follow = NOFOLLOW;

    if (flags & AT_SYMLINK_FOLLOW)
        oldpath_follow = FOLLOW;

    /* find inode for oldpath */
    ECHECK(_path_to_inode(
        ext2,
        oldpath,
        oldpath_follow,
        NULL,
        &ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((*tfs->fs_link)(tfs, locals->suffix, newpath, flags));
        goto done;
    }

    /* oldpath must not be a directory */
    if (S_ISDIR(locals->inode.i_mode))
        ERAISE(-EPERM);

    /* find the parent inode of newpath */
    ECHECK(_split_path(newpath, locals->dirname, locals->filename));
    ECHECK(_path_to_inode(
        ext2,
        locals->dirname,
        NOFOLLOW,
        NULL,
        &dino,
        NULL,
        &locals->dinode,
        NULL,
        NULL));

    /* initialize the new directory entry */
    _dirent_init(&locals->ent, ino, EXT2_FT_REG_FILE, locals->filename);

    /* add the new directory entry (might fail with -EEXIST) */
    ECHECK(_add_dirent(
        ext2, dino, &locals->dinode, locals->filename, &locals->ent));

    /* increment link count of the inode */
    locals->inode.i_links_count++;

    _update_timestamps(&locals->inode, CHANGE);

    /* write the inodes */
    ECHECK(_write_inode(ext2, ino, &locals->inode));
    ECHECK(_write_inode(ext2, dino, &locals->dinode));

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_unlink(myst_fs_t* fs, const char* path)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    ext2_ino_t ino;
    ext2_ino_t dino;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        char suffix[PATH_MAX];
        uint8_t blk[MYST_BLKSIZE];
        ext2_inode_t inode;
        ext2_inode_t dinode;
        char dirname[PATH_MAX];
        char filename[PATH_MAX];
    };
    struct locals* locals = NULL;

    /* check parameters */
    if (!_ext2_valid(ext2) || !path)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* load the inode */
    ECHECK(_path_to_inode(
        ext2,
        path,
        NOFOLLOW,
        &dino,
        &ino,
        &locals->dinode,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((*tfs->fs_unlink)(tfs, locals->suffix));
        goto done;
    }

    /* fail if inode refers to a directory */
    if (S_ISDIR(locals->inode.i_mode))
    {
        ERAISE(ext2_rmdir(fs, path));
        goto done;
    }

    /* remove the directory entry for this file */
    ECHECK(_split_path(path, locals->dirname, locals->filename));
    ECHECK(
        _remove_dirent(ext2, dino, &locals->dinode, locals->filename, false));

    /* unlink the inode */
    ECHECK(_inode_unlink(ext2, ino, &locals->inode));

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    ext2_ino_t ino;
    ext2_ino_t dino;
    struct locals
    {
        char dirname[PATH_MAX];
        char filename[PATH_MAX];
        char suffix[PATH_MAX];
        ext2_inode_t inode;
        ext2_inode_t dinode;
        ext2_dirent_t ent;
    };
    struct locals* locals = NULL;
    size_t target_len;
    myst_fs_t* tfs = NULL;

    if (!_ext2_valid(ext2))
        ERAISE(-EINVAL);

    if (!target || !linkpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Split linkpath into directory and filename */
    ECHECK(_split_path(linkpath, locals->dirname, locals->filename));

    /* Get the inode of the parent directory */
    ECHECK(_path_to_inode(
        ext2,
        locals->dirname,
        FOLLOW,
        NULL,
        &dino,
        NULL,
        &locals->dinode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* append filename and delegate operation to target filesystem */
        if (myst_strlcat(locals->suffix, "/", PATH_MAX) >= PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        if (myst_strlcat(locals->suffix, locals->filename, PATH_MAX) >=
            PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        ECHECK((*tfs->fs_symlink)(tfs, target, locals->suffix));
        goto done;
    }

    /* create the new link inode */
    ECHECK(_create_inode(ext2, 0, (S_IFLNK | 0777), &locals->inode, &ino));

    /* create new entry for this file in the directory inode */
    _dirent_init(&locals->ent, ino, EXT2_FT_SYMLINK, locals->filename);
    ECHECK(_add_dirent(
        ext2, dino, &locals->dinode, locals->filename, &locals->ent));

    /* get the length of the target */
    target_len = strlen(target);

    /* store targets less than 60 bytes in the inode itself */
    if (target_len < 60)
    {
        memcpy(locals->inode.i_block, target, target_len);
        locals->inode.i_size = target_len;
        locals->inode.i_blocks = 0;
    }
    else
    {
        /* write the file content */
        ECHECK(_inode_write_data(
            ext2, ino, &locals->inode, target, strlen(target)));
    }

    /* write the inode */
    ECHECK(_write_inode(ext2, ino, &locals->inode));

done:

    if (locals)
        free(locals);

    return ret;
}

ssize_t ext2_readlink(
    myst_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    ssize_t ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    ext2_ino_t ino;
    void* data = NULL;
    size_t size;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        ext2_inode_t inode;
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!_ext2_valid(ext2) || !pathname || !buf || !bufsiz)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_inode(
        ext2,
        pathname,
        NOFOLLOW,
        NULL,
        &ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_readlink(tfs, locals->suffix, buf, bufsiz));
        goto done;
    }

    if (!S_ISLNK(locals->inode.i_mode))
        ERAISE(-EINVAL);

    ECHECK((_load_file_by_inode(ext2, ino, &locals->inode, &data, &size)));

    size_t min = _min_size(size, bufsiz);
    memcpy(buf, data, min);
    ret = (ssize_t)min;

done:

    if (locals)
        free(locals);

    if (data)
        free(data);

    return ret;
}

int ext2_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    struct locals
    {
        char old_dirname[PATH_MAX];
        char old_filename[PATH_MAX];
        char new_dirname[PATH_MAX];
        char new_filename[PATH_MAX];
        char suffix[PATH_MAX];
        ext2_inode_t old_dinode;
        ext2_inode_t new_dinode;
        ext2_inode_t old_inode;
        ext2_inode_t new_inode;
        ext2_dirent_t ent;
    };
    struct locals* locals = NULL;
    ext2_ino_t old_dino;
    ext2_ino_t old_ino;
    ext2_ino_t new_dino;
    ext2_ino_t new_ino;
    uint8_t file_type;
    myst_fs_t* tfs = NULL;

    /* ATTN: check attempt to make subdirectory a directory of itself */
    /* ATTN: check where newpath contains a prefix of oldpath */
    /* ATTN: handle renaming of symbolic links */

    if (!_ext2_valid(ext2) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Split oldpath and newpath */
    ECHECK(_split_path(newpath, locals->new_dirname, locals->new_filename));
    ECHECK(_split_path(oldpath, locals->old_dirname, locals->old_filename));

    /* find the oldpath inode */
    ECHECK(_path_to_inode(
        ext2,
        oldpath,
        NOFOLLOW,
        &old_dino,
        &old_ino,
        &locals->old_dinode,
        &locals->old_inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_rename(tfs, locals->suffix, newpath));
        goto done;
    }

    /* find the newpath inode if it exists */
    if (_path_to_inode(
            ext2,
            newpath,
            NOFOLLOW,
            &new_dino,
            &new_ino,
            &locals->new_dinode,
            &locals->new_inode,
            NULL,
            NULL) == 0)
    {
        /* succeed if oldpath and newpath refer to the same inode */
        if (new_ino == old_ino)
            goto done;

        /* if oldpath is a directory, newpath must be an empty directory */
        if (S_ISDIR(locals->old_inode.i_mode))
        {
            ECHECK(
                _inode_test_empty_directory(ext2, new_ino, &locals->new_inode));
            locals->new_inode.i_links_count--;
        }

        /* if oldpath is a regular file, newpath cannot be a directory */
        if (!S_ISDIR(locals->old_inode.i_mode) &&
            S_ISDIR(locals->new_inode.i_mode))
        {
            ERAISE(-EISDIR);
        }

        /* unlink newpath */
        ECHECK(_remove_dirent(
            ext2, new_dino, &locals->new_dinode, locals->new_filename, true));
        ECHECK(_inode_unlink(ext2, new_ino, &locals->new_inode));
    }
    else
    {
        /* newpath does not exist so find its parent directory */
        ECHECK(_path_to_inode(
            ext2,
            locals->new_dirname,
            FOLLOW,
            NULL,
            &new_dino,
            NULL,
            &locals->new_dinode,
            NULL,
            NULL));
    }

    /* determine the file type */
    file_type = _mode_to_file_type(locals->old_inode.i_mode);

    /* remove the oldpath directory entry */
    ECHECK(_remove_dirent(
        ext2, old_dino, &locals->old_dinode, locals->old_filename, true));

    /* sync the inodes because _remove_dirent() changes the old inode */
    if (new_dino == old_dino)
        memcpy(&locals->new_dinode, &locals->old_dinode, sizeof(ext2_inode_t));

    /* initialize the new directory entry with the old inode */
    _dirent_init(&locals->ent, old_ino, file_type, locals->new_filename);

    /* add the new directory entry */
    ECHECK(_add_dirent(
        ext2,
        new_dino,
        &locals->new_dinode,
        locals->new_filename,
        &locals->ent));

    /* if oldpath is a directory, update old directory inode */
    if (S_ISDIR(locals->old_inode.i_mode))
    {
        if (new_dino)
        {
            /* If parent directory is same, use the new inode which has the new
             * dirent recorded */
            if (new_dino == old_dino)
            {
                _update_timestamps(&locals->new_dinode, CHANGE);
                ECHECK(_write_inode(ext2, new_dino, &locals->new_dinode));
            }
            else
            {
                _update_timestamps(&locals->old_dinode, CHANGE);
                ECHECK(_write_inode(ext2, old_dino, &locals->old_dinode));
            }
        }
        else /* don't update links if directory already existed */
        {
            locals->new_dinode.i_links_count++;
            _update_timestamps(&locals->new_dinode, CHANGE);
            ECHECK(_write_inode(ext2, new_dino, &locals->new_dinode));
        }
    }

    _update_timestamps(&locals->old_inode, CHANGE);
    ECHECK(_write_inode(ext2, old_ino, &locals->old_inode));

    /* ATTN: update directory parent pointer ("..") */

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf)
{
    int64_t ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file) || !statbuf)
        ERAISE(-EINVAL);

    memset(statbuf, 0, sizeof(struct stat));
    statbuf->st_dev = 0; /* ATTN: ignore device number */
    statbuf->st_ino = file->shared->ino;
    statbuf->st_mode = file->shared->inode.i_mode;
    statbuf->st_nlink = file->shared->inode.i_links_count;
    statbuf->st_uid =
        file->shared->inode.i_uid |
        (((uid_t)file->shared->inode.i_osd2.linux2.i_uid_h) << 16);
    statbuf->st_gid =
        file->shared->inode.i_gid |
        (((uid_t)file->shared->inode.i_osd2.linux2.i_gid_h) << 16);
    statbuf->st_rdev = 0; /* only for special files */
    statbuf->st_size = _inode_get_size(&file->shared->inode);
    statbuf->st_blksize = ext2->block_size;
    statbuf->st_blocks = file->shared->inode.i_blocks;
    statbuf->st_atim.tv_sec = file->shared->inode.i_atime;
    statbuf->st_ctim.tv_sec = file->shared->inode.i_ctime;
    statbuf->st_mtim.tv_sec = file->shared->inode.i_mtime;

done:
    return ret;
}

int ext2_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int64_t ret = 0;
    ext2_ino_t ino;
    ext2_t* ext2 = (ext2_t*)fs;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        ext2_inode_t inode;
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!_ext2_valid(ext2) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_inode(
        ext2,
        pathname,
        FOLLOW,
        NULL,
        &ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_stat(tfs, locals->suffix, statbuf));
        goto done;
    }

    ECHECK(_stat(ext2, &ino, &locals->inode, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int64_t ret = 0;
    ext2_ino_t ino;
    ext2_t* ext2 = (ext2_t*)fs;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        ext2_inode_t inode;
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!_ext2_valid(ext2) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_inode(
        ext2,
        pathname,
        NOFOLLOW,
        NULL,
        &ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_lstat(tfs, locals->suffix, statbuf));
        goto done;
    }

    ECHECK(_stat(ext2, &ino, &locals->inode, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    ECHECK(_ftruncate(ext2, file, length, false));

done:
    return ret;
}

int ext2_truncate(myst_fs_t* fs, const char* path, off_t length)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    ext2_ino_t ino;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        char suffix[PATH_MAX];
        ext2_inode_t inode;
        myst_file_t file;
        myst_file_shared_t file_shared;
    };
    struct locals* locals = NULL;

    /* check parameters */
    if (!ext2 || !path)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* find the inode of the file */
    ECHECK(_path_to_inode(
        ext2,
        path,
        FOLLOW,
        NULL,
        &ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_truncate(tfs, locals->suffix, length));
        goto done;
    }

    /* call _ftruncate() */
    {
        memset(&locals->file, 0, sizeof(myst_file_t));
        locals->file.shared = &locals->file_shared;
        locals->file_shared.magic = FILE_MAGIC;
        locals->file_shared.ino = ino;
        locals->file_shared.inode = locals->inode;
        locals->file_shared.offset = 0;
        locals->file_shared.access = O_WRONLY;
        locals->file_shared.open_flags = O_WRONLY;

        ECHECK(_ftruncate(ext2, &locals->file, length, false));
        locals->inode = locals->file_shared.inode;
        _file_clear(&locals->file);
        _file_shared_clear(&locals->file_shared);
    }

    ret = 0;

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_mkdir(myst_fs_t* fs, const char* path, mode_t mode)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    struct locals* locals = NULL;
    ext2_ino_t dir_ino;
    ext2_ino_t base_ino;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
        char suffix[PATH_MAX];
        ext2_inode_t dir_inode;
        ext2_inode_t base_inode;
        ext2_dirent_t ent;
    };

    /* Check parameters */
    if (!_ext2_valid(ext2) || !path)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* reject all S_IFMT bits except for O_DIRECT */
    if ((mode & S_IFMT) && !(mode & O_DIRECT))
        ERAISE(-EINVAL);

    /* Split the path */
    ECHECK(_split_path(path, locals->dirname, locals->basename));

    /* Read inode for 'dirname' */
    ECHECK(_path_to_inode(
        ext2,
        locals->dirname,
        FOLLOW,
        NULL,
        &dir_ino,
        NULL,
        &locals->dir_inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* append basename and delegate operation to target filesystem */
        if (myst_strlcat(locals->suffix, "/", PATH_MAX) >= PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        if (myst_strlcat(locals->suffix, locals->basename, PATH_MAX) >=
            PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        ECHECK((*tfs->fs_mkdir)(tfs, locals->suffix, mode));
        goto done;
    }

    /* Fail if the directory already exists */
    if (_path_to_inode(
            ext2,
            path,
            FOLLOW,
            NULL,
            &base_ino,
            NULL,
            &locals->base_inode,
            NULL,
            NULL) == 0)
        ERAISE(-EEXIST);

    /* Create the directory inode and its one block */
    ECHECK(_create_dir_inode_and_block(ext2, dir_ino, mode, &base_ino));

    /* Initialize the new directory entry */
    _dirent_init(&locals->ent, base_ino, EXT2_FT_DIR, locals->basename);

    /* Create new entry for this file in the directory inode */
    ECHECK(_add_dirent(
        ext2, dir_ino, &locals->dir_inode, locals->basename, &locals->ent));

done:

    if (locals)
        free(locals);

    return ret;
}

int ext2_rmdir(myst_fs_t* fs, const char* path)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    ext2_ino_t dino;
    ext2_ino_t ino;
    void* data = NULL;
    size_t size;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        char suffix[PATH_MAX];
        ext2_inode_t dinode;
        ext2_inode_t inode;
        myst_file_t file;
        myst_file_shared_t file_shared;
        char dirname[PATH_MAX];
        char filename[PATH_MAX];
    };
    struct locals* locals = NULL;

    /* check parameters */
    if (!_ext2_valid(ext2) || !path)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* load the inode */
    ECHECK(_path_to_inode(
        ext2,
        path,
        FOLLOW,
        &dino,
        &ino,
        &locals->dinode,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_rmdir(tfs, locals->suffix));
        goto done;
    }

    /* fail if not a directory */
    if (!S_ISDIR(locals->inode.i_mode))
        ERAISE(-ENOTDIR);

    /* if directory is not empty */
    if (locals->inode.i_links_count != 2)
        ERAISE(-EINVAL);

    /* fail if the directory is not empty */
    {
        uint32_t count;

        /* load the directory file contents */
        ECHECK(_load_file_by_inode(ext2, ino, &locals->inode, &data, &size));

        /* Disallow removal if directory is non empty */
        ECHECK(_count_dirents(ext2, data, size, &count));

        /* Expect two entries ("." and "..") */
        if (count != 2)
            ERAISE(-ENOTEMPTY);
    }

    /* remove the directory entry for this file */
    ECHECK(_split_path(path, locals->dirname, locals->filename));
    ECHECK(
        _remove_dirent(ext2, dino, &locals->dinode, locals->filename, false));

    /* truncate the file to zero size (to return all the blocks) */
    {
        /* create a dummy file struct */
        memset(&locals->file, 0, sizeof(myst_file_t));
        memset(&locals->file, 0, sizeof(myst_file_t));
        locals->file.shared = &locals->file_shared;
        locals->file_shared.magic = FILE_MAGIC;
        locals->file_shared.ino = ino;
        locals->file_shared.inode = locals->inode;
        locals->file_shared.offset = 0;
        locals->file_shared.access = O_WRONLY;
        locals->file_shared.open_flags = O_WRONLY;
        ECHECK(_ftruncate(ext2, &locals->file, 0, true));
        locals->inode = locals->file_shared.inode;
        _file_clear(&locals->file);
        _file_shared_clear(&locals->file_shared);
    }

    /* return the inode to the free list */
    ECHECK(_put_ino(ext2, ino));

    /* update the super block */
    ECHECK(_write_super_block(ext2));

done:

    if (locals)
        free(locals);

    if (data)
        free(data);

    return ret;
}

int ext2_opendir(myst_fs_t* fs, const char* path, ext2_dir_t** dir_out)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    ext2_dir_t* dir = NULL;

    if (dir_out)
        *dir_out = NULL;

    /* check parameters */
    if (!ext2 || !path || !dir_out)
        ERAISE(-EINVAL);

    /* allocate directory object */
    if (!(dir = (ext2_dir_t*)calloc(1, sizeof(ext2_dir_t))))
        ERAISE(-ENOMEM);

    /* load the blocks for this inode into memory */
    ECHECK((_load_file_by_path(ext2, path, &dir->data, &dir->size)));

    /* set pointer to current directory */
    dir->next = dir->data;

    /* set output parameter */
    *dir_out = dir;
    dir = NULL;

done:

    if (dir)
        free(dir);

    return ret;
}

int ext2_readdir(myst_fs_t* fs, ext2_dir_t* dir, struct dirent** ent_out)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    struct dirent* ent = NULL;

    if (ent_out)
        *ent_out = NULL;

    if (!_ext2_valid(ext2) || !dir || !dir->data || !dir->next)
        ERAISE(-EINVAL);

    /* Find the next entry (possibly skipping padding entries) */
    {
        const void* end = (void*)((char*)dir->data + dir->size);

        while (!ent && dir->next < end)
        {
            const ext2_dirent_t* de = (ext2_dirent_t*)dir->next;

            if (de->rec_len == 0)
                break;

            if (de->name_len > 0)
            {
                /* Found! */

                /* Set struct dirent.d_ino */
                dir->ent.d_ino = de->inode;

                /* Set struct dirent.d_off (not used) */
                dir->ent.d_off = 0;

                /* Set struct dirent.d_reclen (not used) */
                dir->ent.d_reclen = sizeof(struct dirent);

                /* Set struct dirent.type */
                switch (de->file_type)
                {
                    case EXT2_FT_UNKNOWN:
                        dir->ent.d_type = DT_UNKNOWN;
                        break;
                    case EXT2_FT_REG_FILE:
                        dir->ent.d_type = DT_REG;
                        break;
                    case EXT2_FT_DIR:
                        dir->ent.d_type = DT_DIR;
                        break;
                    case EXT2_FT_CHRDEV:
                        dir->ent.d_type = DT_CHR;
                        break;
                    case EXT2_FT_BLKDEV:
                        dir->ent.d_type = DT_BLK;
                        break;
                    case EXT2_FT_FIFO:
                        dir->ent.d_type = DT_FIFO;
                        break;
                    case EXT2_FT_SOCK:
                        dir->ent.d_type = DT_SOCK;
                        break;
                    case EXT2_FT_SYMLINK:
                        dir->ent.d_type = DT_LNK;
                        break;
                    default:
                        dir->ent.d_type = DT_UNKNOWN;
                        break;
                }

                /* Set struct dirent.d_name */
                {
                    size_t n1 = sizeof(dir->ent.d_name);
                    size_t n2 = de->name_len;
                    size_t n = _min_size(n1 - 1, n2);
                    memcpy(dir->ent.d_name, de->name, n);
                    memset(dir->ent.d_name + n, '\0', n1 - n);
                }

                /* Success! */
                ent = &dir->ent;
            }

            /* Position to the next entry (for next call to readdir) */
            dir->next = (void*)((char*)dir->next + de->rec_len);
        }
    }

    if ((*ent_out = ent))
        ret = 1;

done:
    return ret;
}

int ext2_closedir(myst_fs_t* fs, ext2_dir_t* dir)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !dir)
        ERAISE(-EINVAL);

    free(dir->data);
    free(dir);

    ret = 0;

done:
    return ret;
}

static ssize_t _ext2_readv(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    ext2_t* ext2 = (ext2_t*)fs;
    ssize_t ret = 0;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    ret = myst_fdops_readv(&fs->fdops, file, iov, iovcnt);
    ECHECK(ret);

done:
    return ret;
}

static ssize_t _ext2_writev(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    ext2_t* ext2 = (ext2_t*)fs;
    ssize_t ret = 0;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&fs->fdops, file, iov, iovcnt);
    ECHECK(ret);

done:
    return ret;
}

static int _ext2_dup(
    myst_fs_t* fs,
    const myst_file_t* file,
    myst_file_t** file_out)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file) || !file_out)
        ERAISE(-EINVAL);

    if (!(*file_out = (myst_file_t*)calloc(1, sizeof(myst_file_t))))
        ERAISE(-ENOMEM);

    (*file_out)->shared = file->shared;
    (*file_out)->fdflags = 0;

    file->shared->use_count++;
done:

    return ret;
}

static int _ext2_target_fd(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _ext2_get_events(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    /* Regular files always poll TRUE for reads and writes */
    ret |= POLLIN;
    ret |= POLLOUT;

done:
    return ret;
}

static int _ext2_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    (void)source;

    if (!_ext2_valid(ext2) || !target)
        ERAISE(-EINVAL);

    if (strlen(target) >= sizeof(ext2->target))
        ERAISE(-ENAMETOOLONG);

    myst_strlcpy(ext2->target, target, sizeof(ext2->target));

done:
    return ret;
}

static int _ext2_creat(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file)
{
    int ret = 0;
    const int flags = O_CREAT | O_WRONLY | O_TRUNC;

    if (!fs)
        ERAISE(-EINVAL);

    ERAISE((*fs->fs_open)(fs, pathname, flags, mode, fs_out, file));

done:
    return ret;
}

static ssize_t _ext2_pread(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count,
    off_t offset)
{
    ext2_t* ext2 = (ext2_t*)fs;
    ssize_t ret = 0;
    uint64_t old_offset;
    ssize_t n;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (offset < 0)
        ERAISE(-EFAULT);

    /* fail for directories */
    if (S_ISDIR(file->shared->inode.i_mode))
        ERAISE(-EISDIR);

    old_offset = file->shared->offset;
    file->shared->offset = offset;

    n = ext2_read(fs, file, buf, count);
    file->shared->offset = old_offset;
    ECHECK(n);
    ret = n;

done:
    return ret;
}

static ssize_t _ext2_pwrite(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count,
    off_t offset)
{
    ext2_t* ext2 = (ext2_t*)fs;
    ssize_t ret = 0;
    uint64_t old_offset;
    ssize_t n;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (offset < 0)
        ERAISE(-EINVAL);

    /* save the original offset */
    old_offset = file->shared->offset;

    // When opened for append, Linux pwrite() appends data to the end of file
    // regadless of the offset.
    if ((file->shared->operating & O_APPEND))
        file->shared->offset = _inode_get_size(&file->shared->inode);
    else
        file->shared->offset = offset;

    n = ext2_write(fs, file, buf, count);

    /* restore the original offset */
    file->shared->offset = old_offset;

    ECHECK(n);
    ret = n;

done:
    return ret;
}

static int _set_fd_flag(ext2_t* ext2, myst_file_t* file, long arg)
{
    int ret = 0;

    /* Linux currently only defines a single flag, FD_CLOEXEC */
    if (arg & FD_CLOEXEC)
        file->fdflags = FD_CLOEXEC;
    else
        file->fdflags = 0;

    _update_timestamps(&file->shared->inode, CHANGE);
    ECHECK(_write_inode(ext2, file->shared->ino, &file->shared->inode));

done:
    return ret;
}

static int _ext2_fcntl(myst_fs_t* fs, myst_file_t* file, int cmd, long arg)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    switch (cmd)
    {
        case F_SETFD:
        {
            ECHECK(_set_fd_flag(ext2, file, arg));
            goto done;
        }
        case F_GETFD:
        {
            ret = file->fdflags;
            goto done;
        }
        case F_GETFL:
        {
            ret = (int)(file->shared->access | file->shared->operating);
            goto done;
        }
        case F_SETFL:
        {
            if (arg & O_APPEND)
                file->shared->operating |= O_APPEND;
            if (arg & O_NONBLOCK)
                file->shared->operating |= O_NONBLOCK;
            if (arg & O_DIRECT)
                // ATTN: implement O_DIRECT for files
                file->shared->operating |= O_DIRECT;
            if (arg & O_NOATIME)
                // ATTN: implement O_NOATIME for files
                file->shared->operating |= O_NOATIME;
            goto done;
        }
        case F_SETLK:
        case F_SETLKW:
        {
            /* ATTN: silently ignoring locking for now */
            goto done;
        }
        default:
        {
            ERAISE(-ENOTSUP);
        }
    }

done:
    return ret;
}

static int _ext2_ioctl(
    myst_fs_t* fs,
    myst_file_t* file,
    unsigned long request,
    long arg)
{
    ext2_t* ext2 = (ext2_t*)fs;
    int ret = 0;

    (void)arg;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EBADF);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    switch (request)
    {
        case TIOCGWINSZ:
        {
            ERAISE(-EINVAL);
            break;
        }
        case FIOCLEX:
        {
            ECHECK(_set_fd_flag(ext2, file, FD_CLOEXEC));
            break;
        }
        case FIONCLEX:
        {
            ECHECK(_set_fd_flag(ext2, file, 0));
            break;
        }
        case FIONBIO:
        {
            int* val = (int*)arg;

            if (!val)
                ERAISE(-EINVAL);

            if (*val)
                file->shared->operating |= O_NONBLOCK;
            else
                file->shared->operating &= ~O_NONBLOCK;

            break;
        }
        default:
            ERAISE(-ENOTSUP);
    }

done:

    return ret;
}

static int _ext2_realpath(
    myst_fs_t* fs,
    myst_file_t* file,
    char* buf,
    size_t size)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file) || !buf || !size)
        ERAISE(-EINVAL);

    if (strcmp(ext2->target, "/") == 0)
    {
        if (myst_strlcpy(buf, file->shared->realpath, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        if (myst_strlcpy(buf, ext2->target, size) >= size)
            ERAISE(-ENAMETOOLONG);

        if (myst_strlcat(buf, file->shared->realpath, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

static int _ext2_getdents64(
    myst_fs_t* fs,
    myst_file_t* file,
    struct dirent* dirp,
    size_t count)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    size_t n = count / sizeof(struct dirent);
    size_t bytes = 0;

    if (!_ext2_valid(ext2) || !_file_valid(file) || !dirp)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    if (!S_ISDIR(file->shared->inode.i_mode))
        ERAISE(-ENOTDIR);

    if (count == 0)
        goto done;

    /* If file was not opened with O_DIRECTORY, file->shared->dir.data will not
     * have been populated */
    if (file->shared->dir.data == NULL)
    {
        /* refresh the inode */
        ECHECK(
            (ext2_read_inode(ext2, file->shared->ino, &file->shared->inode)));

        /* _load_file perturbs the file offset, save it */
        int saved_offset = file->shared->offset;
        ECHECK(_load_file(
            ext2, file, &file->shared->dir.data, &file->shared->dir.size));
        file->shared->offset = saved_offset;
    }

    /* set next relative to offset in case rewinddir() was called */
    file->shared->dir.next =
        (uint8_t*)file->shared->dir.data + file->shared->offset;

    for (size_t i = 0; i < n; i++)
    {
        int r;
        struct dirent* ent = NULL;

        if ((r = ext2_readdir(&ext2->base, &file->shared->dir, &ent)) < 0)
        {
            ERAISE(r);
        }

        /* break on end of file */
        if (r == 0)
            break;

        *dirp = *ent;
        bytes += sizeof(struct dirent);
        dirp++;

        /* update the file offset */
        file->shared->offset =
            (uint8_t*)file->shared->dir.next - (uint8_t*)file->shared->dir.data;
    }

    ret = (int)bytes;

done:
    return ret;
}

static int _statfs(ext2_t* ext2, struct statfs* buf)
{
    int ret = 0;

    if (!buf)
        ERAISE(-EINVAL);

    memset(buf, 0, sizeof(struct statfs));
    buf->f_type = ext2->sb.s_magic;
    buf->f_bsize = ext2->block_size;
    buf->f_blocks = ext2->sb.s_blocks_count;
    buf->f_bfree = ext2->sb.s_free_blocks_count;
    buf->f_bavail = ext2->sb.s_free_blocks_count;

done:
    return ret;
}

static int _ext2_statfs(myst_fs_t* fs, const char* path, struct statfs* buf)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        char suffix[PATH_MAX];
        ext2_inode_t inode;
    };
    struct locals* locals = NULL;

    if (!_ext2_valid(ext2) || !path || !buf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ext2,
        path,
        FOLLOW,
        NULL,
        NULL,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_statfs(tfs, locals->suffix, buf));
        goto done;
    }
    ECHECK(_statfs(ext2, buf));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _ext2_fstatfs(myst_fs_t* fs, myst_file_t* file, struct statfs* buf)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file) || !buf)
        ERAISE(-EINVAL);

    ECHECK(_statfs(ext2, buf));

done:
    return ret;
}

static int _ext2_futimens(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct timespec times[2])
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (times)
    {
        switch (times[0].tv_nsec)
        {
            case UTIME_OMIT:
                break;
            case UTIME_NOW:
                _update_timestamps(&file->shared->inode, ACCESS);
                break;
            default:
            {
                const struct timespec* ts = &times[0];
                uint32_t sec = ts->tv_sec + (ts->tv_nsec / NANO_IN_SECOND);
                file->shared->inode.i_atime = sec;
                break;
            }
        }

        switch (times[1].tv_nsec)
        {
            case UTIME_OMIT:
                break;
            case UTIME_NOW:
                _update_timestamps(&file->shared->inode, MODIFY);
                break;
            default:
            {
                const struct timespec* ts = &times[1];
                uint32_t sec = ts->tv_sec + (ts->tv_nsec / NANO_IN_SECOND);
                file->shared->inode.i_mtime = sec;
                break;
            }
        }
    }
    else
    {
        /* set to current time */
        _update_timestamps(&file->shared->inode, ACCESS | MODIFY);
    }

    ECHECK(_write_inode(ext2, file->shared->ino, &file->shared->inode));

done:
    return ret;
}

static int _chown(ext2_inode_t* inode, uid_t owner, gid_t group)
{
    int ret = 0;

    if (!inode)
        ERAISE(-EINVAL);

    if (owner != -1)
    {
        inode->i_uid = owner & 0xFFFF;
        inode->i_osd2.linux2.i_uid_h = owner >> 16;
    }

    if (group != -1)
    {
        inode->i_gid = group & 0xFFFF;
        inode->i_osd2.linux2.i_gid_h = group >> 16;
    }

    /* For executables, clear set-user-ID and set-group-ID bits */
    if (inode->i_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
    {
        inode->i_mode &= ~S_ISUID;

        /* Only clear set-group-id bit for group executables */
        if ((inode->i_mode & S_ISGID) && (inode->i_mode & S_IXGRP))
            inode->i_mode &= ~S_ISGID;
    }

    _update_timestamps(inode, CHANGE);

done:
    return ret;
}

static int _ext2_chown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    struct locals
    {
        ext2_ino_t ino;
        ext2_inode_t inode;
        char suffix[PATH_MAX];
    }* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ext2_valid(ext2) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ext2,
        pathname,
        FOLLOW,
        NULL,
        &locals->ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((ret = tfs->fs_chown(tfs, locals->suffix, owner, group)));
        goto done;
    }

    ECHECK(_chown(&locals->inode, owner, group));

    /* persist the inode change */
    ECHECK(_write_inode(ext2, locals->ino, &locals->inode));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _ext2_fchown(
    myst_fs_t* fs,
    myst_file_t* file,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !file)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* refresh the inode */
    ECHECK((ext2_read_inode(ext2, file->shared->ino, &file->shared->inode)));

    ECHECK(_chown(&file->shared->inode, owner, group));

    /* persist the inode change */
    ECHECK(_write_inode(ext2, file->shared->ino, &file->shared->inode));

done:
    return ret;
}

static int _ext2_lchown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    struct locals
    {
        ext2_ino_t ino;
        ext2_inode_t inode;
        char suffix[PATH_MAX];
    }* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ext2_valid(ext2) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ext2,
        pathname,
        NOFOLLOW,
        NULL,
        &locals->ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((ret = tfs->fs_lchown(tfs, locals->suffix, owner, group)));
        goto done;
    }

    _chown(&locals->inode, owner, group);

    /* persist the inode change */
    ECHECK(_write_inode(ext2, locals->ino, &locals->inode));

done:

    if (locals)
        free(locals);

    return ret;
}

#define ALLPERMS (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

static int _chmod(ext2_inode_t* inode, mode_t mode)
{
    int ret = 0;
    myst_thread_t* self = myst_thread_self();

    if (!inode)
        ERAISE(-EINVAL);

    inode->i_mode &= ~ALLPERMS;
    inode->i_mode |= (mode & ALLPERMS);

    /* If not privileged and inode not in thread's primary or supplementary
     * groups, drop S_ISGID bit */
    if ((inode->i_mode & S_ISGID) && self->euid != 0 &&
        (check_thread_group_membership(inode->i_gid) != 0))
    {
        inode->i_mode &= ~S_ISGID;
    }

    _update_timestamps(inode, CHANGE);

done:
    return ret;
}

static int _ext2_chmod(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;
    struct locals
    {
        ext2_ino_t ino;
        ext2_inode_t inode;
        char suffix[PATH_MAX];
    }* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ext2_valid(ext2) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ext2,
        pathname,
        FOLLOW,
        NULL,
        &locals->ino,
        NULL,
        &locals->inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_chmod(tfs, locals->suffix, mode)));
        goto done;
    }

    ECHECK(_chmod(&locals->inode, mode));

    /* persist the inode change */
    ECHECK(_write_inode(ext2, locals->ino, &locals->inode));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _ext2_fchmod(myst_fs_t* fs, myst_file_t* file, mode_t mode)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !file)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* refresh the inode */
    ECHECK((ext2_read_inode(ext2, file->shared->ino, &file->shared->inode)));

    ECHECK(_chmod(&file->shared->inode, mode));

    /* persist the inode change */
    ECHECK(_write_inode(ext2, file->shared->ino, &file->shared->inode));

done:
    return ret;
}

static int _ext2_fsync_and_fdatasync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !file)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* Changes to ext2 files are ephemeral, and are not written
     to back to the on-disk image. So we treat fsync and fdatasync as a NOP */

done:

    return ret;
}

static int _ext2_release_tree(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !pathname)
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:

    return ret;
}

static myst_fs_t _base = {
    {
        .fd_read = (void*)ext2_read,
        .fd_write = (void*)ext2_write,
        .fd_readv = (void*)_ext2_readv,
        .fd_writev = (void*)_ext2_writev,
        .fd_fstat = (void*)ext2_fstat,
        .fd_fcntl = (void*)_ext2_fcntl,
        .fd_ioctl = (void*)_ext2_ioctl,
        .fd_dup = (void*)_ext2_dup,
        .fd_close = (void*)ext2_close,
        .fd_target_fd = (void*)_ext2_target_fd,
        .fd_get_events = (void*)_ext2_get_events,
    },
    .fs_release = ext2_release,
    .fs_mount = _ext2_mount,
    .fs_creat = _ext2_creat,
    .fs_open = ext2_open,
    .fs_lseek = ext2_lseek,
    .fs_read = ext2_read,
    .fs_write = ext2_write,
    .fs_pread = _ext2_pread,
    .fs_pwrite = _ext2_pwrite,
    .fs_readv = _ext2_readv,
    .fs_writev = _ext2_writev,
    .fs_close = ext2_close,
    .fs_access = ext2_access,
    .fs_stat = ext2_stat,
    .fs_lstat = ext2_lstat,
    .fs_fstat = ext2_fstat,
    .fs_link = ext2_link,
    .fs_unlink = ext2_unlink,
    .fs_rename = ext2_rename,
    .fs_truncate = ext2_truncate,
    .fs_ftruncate = ext2_ftruncate,
    .fs_mkdir = ext2_mkdir,
    .fs_rmdir = ext2_rmdir,
    .fs_getdents64 = _ext2_getdents64,
    .fs_readlink = ext2_readlink,
    .fs_symlink = ext2_symlink,
    .fs_realpath = _ext2_realpath,
    .fs_fcntl = _ext2_fcntl,
    .fs_ioctl = _ext2_ioctl,
    .fs_dup = _ext2_dup,
    .fs_target_fd = _ext2_target_fd,
    .fs_get_events = _ext2_get_events,
    .fs_statfs = _ext2_statfs,
    .fs_fstatfs = _ext2_fstatfs,
    .fs_futimens = _ext2_futimens,
    .fs_chown = _ext2_chown,
    .fs_fchown = _ext2_fchown,
    .fs_lchown = _ext2_lchown,
    .fs_chmod = _ext2_chmod,
    .fs_fchmod = _ext2_fchmod,
    .fs_fdatasync = _ext2_fsync_and_fdatasync,
    .fs_fsync = _ext2_fsync_and_fdatasync,
    .fs_release_tree = _ext2_release_tree,
};

int ext2_create(
    myst_blkdev_t* dev,
    myst_fs_t** fs_out,
    myst_mount_resolve_callback_t resolve_cb)
{
    int ret = 0;
    ext2_t* ext2 = NULL;

    /* Initialize output parameters */
    if (fs_out)
        *fs_out = NULL;

    /* Check parameters */
    if (!dev || !fs_out)
        ERAISE(-EINVAL);

    /* Allocate the file system object */
    if (!(ext2 = (ext2_t*)calloc(1, sizeof(ext2_t))))
        ERAISE(-ENOMEM);

    /* Read the superblock */
    ECHECK(_read_super_block(dev, &ext2->sb));

    /* Allocate the array of inode references */
    if (!(ext2->inode_refs =
              calloc(ext2->sb.s_inodes_count, sizeof(ext2_inode_ref_t))))
    {
        ERAISE(-ENOMEM);
    }

    /* initialize the base structure */
    memcpy(&ext2->base, &_base, sizeof(myst_fs_t));

    /* Set the file object */
    ext2->dev = dev;

    /* Set the mount resolve callback */
    ext2->resolve = resolve_cb;

    /* Check the superblock magic number */
    if (ext2->sb.s_magic != EXT2_S_MAGIC)
        ERAISE(-EINVAL);

    /* Reject revision 0 file systems */
    if (ext2->sb.s_rev_level == EXT2_GOOD_OLD_REV)
        ERAISE(-EINVAL);

    /* Accept revision 1 file systems */
    if (ext2->sb.s_rev_level < EXT2_DYNAMIC_REV)
        ERAISE(-EINVAL);

    /* Check inode size */
    if (ext2->sb.s_inode_size > sizeof(ext2_inode_t))
        ERAISE(-EINVAL);

    /* Calcualte the block size in bytes */
    ext2->block_size = 1024 << ext2->sb.s_log_block_size;

    /* Calculate the number of block groups */
    ext2->group_count =
        1 + (ext2->sb.s_blocks_count - 1) / ext2->sb.s_blocks_per_group;

    /* Get the groups list */
    if (!(ext2->groups = _read_groups(ext2)))
        ERAISE(-EIO);

    /* Read the root inode */
    if ((ret = ext2_read_inode(ext2, EXT2_ROOT_INO, &ext2->root_inode)))
        ERAISE(-EIO);

    *fs_out = &ext2->base;
    ext2 = NULL;

    ret = 0;

done:

    if (ext2)
    {
        if (ext2->inode_refs)
            free(ext2->inode_refs);

        if (ext2->groups)
            free(ext2->groups);

        free(ext2);
    }

    return ret;
}

int ext2_set_wrapper_fs(myst_fs_t* fs, myst_fs_t* wrapper_fs)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2) || !wrapper_fs)
        ERAISE(-EINVAL);

    ext2->wrapper_fs = wrapper_fs;

done:
    return ret;
}

int ext2_release(myst_fs_t* fs)
{
    int ret = 0;
    ext2_t* ext2 = (ext2_t*)fs;

    if (!_ext2_valid(ext2))
        ERAISE(-EINVAL);

    if (ext2->groups)
        free(ext2->groups);

    if (ext2->inode_refs)
        free(ext2->inode_refs);

    if (ext2->dev)
        (*ext2->dev->close)(ext2->dev);

    free(ext2);

done:
    return ret;
}
