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
#include <myst/list.h>
#include <myst/spinlock.h>

#define MAX_CACHE_CHAINS (64 * 1024)
#define LOOKAHEAD_SIZE 8
#define MAX_LOOKAHEAD_QUEUE_SIZE 4
#define USE_LRU
#define LRU_LIST_SIZE 2
#define MAX_LRU_CHAINS 32
#define FREE_LIST_SIZE 64

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
    cache_block_t* chains[MAX_CACHE_CHAINS];
    myst_list_t lookahead; /* read lookahead list */
#ifdef USE_LRU
    myst_list_t lru[MAX_LRU_CHAINS]; /* LRU lists indexed by blkno % LRU */
#endif
} blkdev_t;

typedef struct lookahead_buf
{
    myst_list_node_t base;
    uint64_t blkno;
    myst_block_t data[MYST_BLKSIZE];
} lookahead_buf_t;

typedef struct node
{
    myst_list_node_t base;
    uint64_t blkno;
    uint8_t data[MYST_BLKSIZE];
} node_t;

/* free list */
static myst_list_t _free;
static myst_spinlock_t _free_lock;

__attribute__((__unused__)) static node_t* _get_node(void)
{
    myst_spin_lock(&_free_lock);

    if (_free.head)
    {
        node_t* p = (node_t*)_free.head;
        myst_list_remove(&_free, &p->base);
        myst_spin_unlock(&_free_lock);
        return p;
    }

    myst_spin_unlock(&_free_lock);

    return malloc(sizeof(node_t));
}

__attribute__((__unused__)) static void _put_node(node_t* p)
{
    myst_spin_lock(&_free_lock);

    if (_free.size < FREE_LIST_SIZE)
    {
        myst_list_prepend(&_free, &p->base);
        myst_spin_unlock(&_free_lock);
        return;
    }

    myst_spin_unlock(&_free_lock);

    free(p);
}

/* free lookahead_buf_t list */
static myst_list_t _free_lookahead;
static myst_spinlock_t _free_lookahead_lock;

__attribute__((__unused__)) static lookahead_buf_t* _get_lookahead_buf(void)
{
    myst_spin_lock(&_free_lookahead_lock);

    if (_free_lookahead.head)
    {
        lookahead_buf_t* p = (lookahead_buf_t*)_free_lookahead.head;
        myst_list_remove(&_free_lookahead, &p->base);
        myst_spin_unlock(&_free_lookahead_lock);
        return p;
    }

    myst_spin_unlock(&_free_lookahead_lock);

    return malloc(sizeof(lookahead_buf_t));
}

__attribute__((__unused__)) static void _put_lookahead_buf(lookahead_buf_t* p)
{
    myst_spin_lock(&_free_lookahead_lock);

    if (_free_lookahead.size < FREE_LIST_SIZE)
    {
        myst_list_prepend(&_free_lookahead, &p->base);
        myst_spin_unlock(&_free_lookahead_lock);
        return;
    }

    myst_spin_unlock(&_free_lookahead_lock);

    free(p);
}

static void _release_cache(blkdev_t* dev)
{
    size_t i;

    for (i = 0; i < MAX_CACHE_CHAINS; i++)
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
    size_t slot = blkno % MAX_CACHE_CHAINS;

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
    size_t slot = blkno % MAX_CACHE_CHAINS;
    cache_block_t* block;

    /* Allocate new block */
    if (!(block = malloc(sizeof(cache_block_t))))
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

    myst_list_free(&impl->lookahead);
    myst_list_free(&_free_lookahead);

#ifdef USE_LRU
    {
        size_t i;
        for (i = 0; i < MAX_LRU_CHAINS; i++)
        {
            myst_list_free(&impl->lru[i]);
        }
        myst_list_free(&_free);
    }
#endif

    ECHECK(myst_close_block_device(impl->fd));
    free(impl);

done:
    return ret;
}

static int _get(myst_blkdev_t* dev, uint64_t blkno, void* data)
{
    int ret = 0;
    blkdev_t* impl = (blkdev_t*)dev;
    lookahead_buf_t* buf = NULL;

    if (!dev || !data)
        ERAISE(-EINVAL);

    /* first check the cache */
    if (impl->ephemeral)
    {
        const cache_block_t* cache_block;

        if ((cache_block = _get_cache(impl, blkno)))
        {
            memcpy(data, cache_block->data, MYST_BLKSIZE);
            goto done;
        }
    }

#ifdef USE_LRU
    /* next check the least-recently used cache */
    {
        size_t slot = blkno % MAX_LRU_CHAINS;
        node_t* p = (node_t*)impl->lru[slot].head;
        node_t* prev = NULL;

        while (p)
        {
            if (p->blkno == blkno)
            {
                memcpy(data, p->data, MYST_BLKSIZE);

                if (prev)
                {
                    myst_list_remove(&impl->lru[slot], &p->base);
                    myst_list_prepend(&impl->lru[slot], &p->base);
                }
                goto done;
            }

            p = (node_t*)p->base.next;
            prev = p;
        }
    }
#endif /* USE_LRU */

    /* check the lookahead cache */
    {
        lookahead_buf_t* p = (lookahead_buf_t*)impl->lookahead.head;

        while (p)
        {
            if (blkno >= p->blkno && blkno < p->blkno + LOOKAHEAD_SIZE)
            {
                size_t index = blkno - p->blkno;
                memcpy(data, &p->data[index], MYST_BLKSIZE);
                goto done;
            }

            p = (lookahead_buf_t*)p->base.next;
        }
    }

    const uint64_t rawblkno = blkno + impl->blkno_offset;
    ssize_t n;

    if (!(buf = _get_lookahead_buf()))
        ERAISE(-ENOMEM);

    ECHECK(
        n = myst_read_block_device(
            impl->fd, rawblkno, &buf->data[0], LOOKAHEAD_SIZE));

    if (n == 0)
        ERAISE(-EIO);

    /* copy the first block */
    memcpy(data, &buf->data[0], MYST_BLKSIZE);

#ifdef USE_LRU
    /* prepend this block to the least-recently used list */
    {
        node_t* p;
        size_t slot = blkno % MAX_LRU_CHAINS;

        /* allocate a new  node */
        if (!(p = _get_node()))
            ERAISE(-ENOMEM);

        /* initialize the node */
        p->blkno = blkno;
        memcpy(p->data, &buf->data[0], sizeof(p->data));

        /* prepend the new node */
        myst_list_prepend(&impl->lru[slot], &p->base);

        /* evict the least-recently used node */
        if (impl->lru[slot].size > LRU_LIST_SIZE)
        {
            node_t* tail;

            if ((tail = (node_t*)impl->lru[slot].tail))
                myst_list_remove(&impl->lru[slot], &tail->base);

            _put_node(tail);
        }
    }
#endif /* USE_LRU */

    /* append the buffer to the lookahead list */
    {
        buf->blkno = blkno;

        myst_list_append(&impl->lookahead, &buf->base);
        buf = NULL;

        /* remove the first node if list has grown too large */
        if (impl->lookahead.size > MAX_LOOKAHEAD_QUEUE_SIZE)
        {
            lookahead_buf_t* p;

            if ((p = (lookahead_buf_t*)impl->lookahead.head))
            {
                myst_list_remove(&impl->lookahead, &p->base);
                _put_lookahead_buf(p);
            }
        }
    }

done:

    if (buf)
        _put_lookahead_buf(buf);

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
