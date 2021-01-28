// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <myst/blkdev.h>
#include <myst/blockdevice.h>
#include <myst/eraise.h>

#define MAX_CHAINS (64 * 1024)

typedef struct cache_block cache_block_t;

struct cache_block
{
    cache_block_t* next;
    uint64_t blkno;
    uint8_t data[MYST_BLKSIZE];
};

typedef struct blkdev
{
    myst_blkdev_t base;
    bool ephemeral;
    uint64_t blkno_offset;
    int fd;
    cache_block_t* chains[MAX_CHAINS];
} blkdev_t;

static void _release_cache(blkdev_t* dev)
{
    size_t i;

    for (i = 0; i < MAX_CHAINS; i++)
    {
        cache_block_t* p;
        cache_block_t* next;

        for (p = dev->chains[i]; p; p = next)
        {
            next = p->next;
            free(p);
        }
    }
}

static cache_block_t* _get_cache(blkdev_t* dev, uint64_t blkno)
{
    cache_block_t* p;
    size_t slot = blkno % MAX_CHAINS;

    for (p = dev->chains[slot]; p; p = p->next)
    {
        if (p->blkno == blkno)
            return p;
    }

    return NULL;
}

static int _put_cache(blkdev_t* dev, uint64_t blkno, const void* data)
{
    int rc = -1;
    size_t slot = blkno % MAX_CHAINS;
    cache_block_t* block;

    /* Allocate new block */
    if (!(block = calloc(1, sizeof(cache_block_t))))
        goto done;

    /* Initialize the block */
    memcpy(block->data, data, sizeof(block->data));
    block->blkno = blkno;

    /* Add to cache */
    block->next = dev->chains[slot];
    dev->chains[slot] = block;

    rc = 0;

done:
    return rc;
}

static int _close(myst_blkdev_t* dev)
{
    int ret = 0;
    blkdev_t* impl = (blkdev_t*)dev;

    if (!dev)
        ERAISE(-EINVAL);

    if (impl->ephemeral)
        _release_cache(impl);

    ECHECK(myst_close_block_device(impl->fd));
    free(impl);

done:
    return ret;
}

static int _get(myst_blkdev_t* dev, uint64_t blkno, void* data)
{
    int ret = 0;
    blkdev_t* impl = (blkdev_t*)dev;

    if (!dev || !data)
        ERAISE(-EINVAL);

    /* check the cache */
    if (impl->ephemeral)
    {
        const cache_block_t* cache_block;

        if ((cache_block = _get_cache(impl, blkno)))
        {
            memcpy(data, cache_block->data, MYST_BLKSIZE);
            goto done;
        }
    }

    const uint64_t rawblkno = blkno + impl->blkno_offset;
    ECHECK(myst_read_block_device(impl->fd, rawblkno, data, 1));

done:
    return ret;
}

static int _put(myst_blkdev_t* dev, uint64_t blkno, const void* data)
{
    int ret = 0;
    blkdev_t* impl = (blkdev_t*)dev;

    if (!dev || !data)
        ERAISE(-EINVAL);

    /* put the block in the cache */
    if (impl->ephemeral)
    {
        cache_block_t* cache_block;

        if ((cache_block = _get_cache(impl, blkno)))
        {
            memcpy(cache_block->data, data, MYST_BLKSIZE);
        }
        else if (_put_cache(impl, blkno, data) != 0)
        {
            ERAISE(-ENOMEM);
        }

        goto done;
    }

    const uint64_t rawblkno = blkno + impl->blkno_offset;
    ECHECK(myst_write_block_device(impl->fd, rawblkno, data, 1));

done:
    return ret;
}

int myst_rawblkdev_open(
    const char* path,
    bool ephemeral,
    uint64_t blkno_offset,
    myst_blkdev_t** dev)
{
    long ret = 0;
    blkdev_t* impl = NULL;
    int fd;

    if (dev)
        *dev = NULL;

    if (!path || !dev)
        ERAISE(-EINVAL);

    if ((fd = myst_open_block_device(path, ephemeral)) < 0)
        ERAISE(-errno);

    if (!(impl = calloc(1, sizeof(blkdev_t))))
        ERAISE(-ENOMEM);

    impl->base.close = _close;
    impl->base.get = _get;
    impl->base.put = _put;
    impl->ephemeral = ephemeral;
    impl->blkno_offset = blkno_offset;
    impl->fd = fd;

    *dev = &impl->base;
    impl = NULL;

done:

    if (impl)
        free(impl);

    return ret;
}
