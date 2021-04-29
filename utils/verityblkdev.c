// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <myst/blkdev.h>
#include <myst/blockdevice.h>
#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/hex.h>
#include <myst/list.h>
#include <myst/round.h>
#include <myst/sha256.h>
#include <myst/verity.h>

#define VERITYBLKDEV_MAGIC 0x5acdeed9

#define MAX_ROOTHASH_SIZE 256

#define MAX_CHAINS (64 * 1024)

#define MAX_CACHE_BLOCKS 32

MYST_STATIC_ASSERT(sizeof(myst_verity_sb_t) == MYST_BLKSIZE);

typedef struct cache_block
{
    /* links for the hash table chains */
    /* caution: these fields must be first to align with myst_list_node_t */
    struct cache_block* prev;
    struct cache_block* next;

    /* links for the LRU list (where first is least recently used) */
    struct cache_block* lru_prev;
    struct cache_block* lru_next;

    /* the index to the chains[] entry that contains this node */
    size_t slot;

    /* the block number of this data */
    uint64_t blkno;

    /* whether block is dirty (has been written to) */
    bool dirty;

    /* the data for this block */
    uint8_t data[];
} cache_block_t;

typedef struct blkdev
{
    myst_blkdev_t base;
    uint32_t magic;
    size_t first_hash_blkno; /* hash offset in block numbers */
    uint8_t roothash[MAX_ROOTHASH_SIZE];
    size_t roothash_size;
    int rawblkdev;
    myst_verity_sb_t sb;
    myst_buf_t hashtree;
    myst_list_t chains[MAX_CHAINS];
    struct
    {
        cache_block_t* head;
        cache_block_t* tail;
        size_t size;
    } lru;
    size_t max_cache_blocks;
    const uint8_t* leaves_start;
    const uint8_t* leaves_end;
    size_t num_leaves;
} blkdev_t;

typedef struct block
{
    uint8_t data[4096];
} block_t;

/*
**==============================================================================
**
** local definitions:
**
**==============================================================================
*/

static size_t _next_multiple(size_t x, size_t m)
{
    return (x + m - 1) / m;
}

static __inline__ size_t _min_size(size_t x, size_t y)
{
    return x < y ? x : y;
}

static int _hash2(
    const void* s1,
    size_t n1,
    const void* s2,
    size_t n2,
    myst_sha256_t* hash)
{
    int ret = 0;
    myst_sha256_ctx_t ctx;

    ECHECK(myst_sha256_start(&ctx));
    ECHECK(myst_sha256_update(&ctx, s1, n1));
    ECHECK(myst_sha256_update(&ctx, s2, n2));
    ECHECK(myst_sha256_finish(&ctx, hash));

done:
    return ret;
}

/*
**==============================================================================
**
** cache implementation:
**
**==============================================================================
*/

static void _lru_append(blkdev_t* dev, cache_block_t* cb)
{
    if (dev->lru.tail)
    {
        cb->lru_next = NULL;
        cb->lru_prev = dev->lru.tail;
        dev->lru.tail->lru_next = cb;
        dev->lru.tail = cb;
    }
    else
    {
        cb->lru_next = NULL;
        cb->lru_prev = NULL;
        dev->lru.head = cb;
        dev->lru.tail = cb;
    }

    dev->lru.size++;
}

static void _lru_remove(blkdev_t* dev, cache_block_t* cb)
{
    if (cb->lru_prev)
        cb->lru_prev->lru_next = cb->lru_next;
    else
        dev->lru.head = cb->lru_next;

    if (cb->lru_next)
        cb->lru_next->lru_prev = cb->lru_prev;
    else
        dev->lru.tail = cb->lru_prev;

    dev->lru.size--;
}

static cache_block_t* _new_cache_block(blkdev_t* dev)
{
    cache_block_t* p;
    const size_t size = sizeof(cache_block_t) + dev->sb.data_block_size;

    if ((p = malloc(size)))
    {
        /* dot not clear the data[] array portion */
        memset(p, 0, sizeof(cache_block_t));
    }

    return p;
}

static void _release_cache(blkdev_t* dev)
{
    for (size_t i = 0; i < MAX_CHAINS; i++)
    {
        cache_block_t* head = (cache_block_t*)dev->chains[i].head;

        for (cache_block_t* p = head; p;)
        {
            cache_block_t* next = p->next;
            free(p);
            p = next;
        }
    }
}

static cache_block_t* _get_cache(blkdev_t* dev, uint64_t blkno)
{
    cache_block_t* p;
    const size_t slot = blkno % MAX_CHAINS;
    cache_block_t* head = (cache_block_t*)dev->chains[slot].head;

    for (p = head; p; p = p->next)
    {
        if (p->blkno == blkno)
            break;
    }

    /* if found, not dirty, and not the only entry; move to the back of the LRU
     * list */
    if (p && p != head && !p->dirty)
    {
        _lru_remove(dev, p);
        _lru_append(dev, p);
    }

    return p;
}

static void _cache_evict(blkdev_t* dev)
{
    if (dev->lru.size >= dev->max_cache_blocks)
    {
        /* evict the first block on the LRU list */
        cache_block_t* cb = dev->lru.head;

        assert(cb->dirty == false);

        /* remove from the chain */
        myst_list_remove(&dev->chains[cb->slot], (myst_list_node_t*)cb);

        /* remove from the LRU list */
        _lru_remove(dev, cb);

        /* release the cache block */
        free(cb);
    }
}

static int _put_cache(blkdev_t* dev, uint64_t blkno, const void* data)
{
    int ret = 0;
    const size_t slot = blkno % MAX_CHAINS;
    cache_block_t* p;

    /* allocate new block */
    if (!(p = _new_cache_block(dev)))
        ERAISE(-ENOMEM);

    /* initialize the block */
    p->slot = slot;
    p->blkno = blkno;
    memcpy(p->data, data, dev->sb.data_block_size);

    /* insert into the given hash table chain */
    myst_list_prepend(&dev->chains[slot], (myst_list_node_t*)p);

    /* insert at end of the LRU list */
    _lru_append(dev, p);

    /* evict the LRU block if necessary */
    _cache_evict(dev);

done:
    return ret;
}

/*
**==============================================================================
**
** Verity block device implementation:
**
**==============================================================================
*/

static bool _blkdev_valid(blkdev_t* dev)
{
    return dev != NULL && dev->magic == VERITYBLKDEV_MAGIC;
}

static int _read_superblock(
    int rawblkdev,
    size_t first_hash_blkno,
    myst_verity_sb_t* sb)
{
    int ret = 0;
    struct vars
    {
        myst_block_t block;
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    ECHECK(myst_read_block_device(rawblkdev, first_hash_blkno, &v->block, 1));

    memcpy(sb, v->block.data, sizeof(myst_verity_sb_t));

    if (memcmp(sb->signature, "verity\0\0", 8) != 0)
        ERAISE(-EINVAL);

done:

    if (v)
        free(v);

    return ret;
}

static int _read_block(
    blkdev_t* dev,
    size_t block_size,
    size_t blkno_offset,
    size_t blkno,
    block_t* block)
{
    int ret = 0;
    const size_t count = block_size / MYST_BLKSIZE;
    const size_t rawblkno = blkno_offset + (blkno * count);
    myst_block_t* blocks = (myst_block_t*)block;

    ECHECK(myst_read_block_device(dev->rawblkdev, rawblkno, blocks, count));

done:
    return ret;
}

static int _read_hash_block(blkdev_t* dev, size_t blkno, block_t* block)
{
    int ret = 0;
    const size_t block_size = dev->sb.hash_block_size;
    const size_t blkno_offset = dev->first_hash_blkno;

    ECHECK(_read_block(dev, block_size, blkno_offset, blkno, block));

done:
    return ret;
}

static int _read_data_block(blkdev_t* dev, size_t blkno, block_t* block)
{
    int ret = 0;
    const size_t block_size = dev->sb.data_block_size;
    const size_t blkno_offset = 0;
    myst_sha256_t hash;

    /* read the block from the underlying deivce */
    ECHECK(_read_block(dev, block_size, blkno_offset, blkno, block));

    /* calculate the hash of this block */
    _hash2(dev->sb.salt, dev->sb.salt_size, block, block_size, &hash);

    /* verify the hash of this block against the hash tree */
    {
        const size_t hash_size = sizeof(myst_sha256_t);
        const uint8_t* phash = dev->leaves_start + blkno * hash_size;

        assert(phash >= dev->leaves_start && phash < dev->leaves_end);

        if (memcmp(&hash, phash, hash_size) != 0)
        {
            memset(block, 0, block_size);
            ERAISE(-EIO);
        }
    }

done:
    return ret;
}

static int _get_raw_block(blkdev_t* dev, size_t rawblkno, void* data)
{
    int ret = 0;
    const size_t block_factor = dev->sb.data_block_size / MYST_BLKSIZE;
    const size_t blkno = rawblkno / block_factor;
    const size_t offset = (rawblkno % block_factor) * MYST_BLKSIZE;
    const cache_block_t* cb;
    const uint8_t* ptr;
    struct vars
    {
        block_t block;
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    /* first check the cache */
    if ((cb = _get_cache(dev, blkno)))
    {
        ptr = cb->data;
    }
    else
    {
        ECHECK(_read_data_block(dev, blkno, &v->block));
        ECHECK(_put_cache(dev, blkno, v->block.data));
        ptr = v->block.data;
    }

    memcpy(data, ptr + offset, MYST_BLKSIZE);

done:

    if (v)
        free(v);

    return ret;
}

static int _put_raw_block(blkdev_t* dev, size_t rawblkno, const void* data)
{
    int ret = 0;
    const size_t block_factor = dev->sb.data_block_size / MYST_BLKSIZE;
    const size_t blkno = rawblkno / block_factor;
    const size_t offset = (rawblkno % block_factor) * MYST_BLKSIZE;
    cache_block_t* cb;
    struct vars
    {
        block_t block;
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    /* if the block is in the cache then update it */
    if ((cb = _get_cache(dev, blkno)))
    {
        memcpy(cb->data + offset, data, MYST_BLKSIZE);

        /* remove this block from LRU list so it won't be evicted */
        if (!cb->dirty)
        {
            _lru_remove(dev, cb);
            cb->dirty = true;
        }
    }
    else
    {
        /* read the data block from disk */
        ECHECK(_read_data_block(dev, blkno, &v->block));

        /* update the data block buffer */
        memcpy(v->block.data + offset, data, MYST_BLKSIZE);

        /* add the new block to the cache */
        ECHECK(_put_cache(dev, blkno, v->block.data));
    }

done:

    if (v)
        free(v);

    return ret;
}

static int _load_hash_tree(blkdev_t* dev)
{
    int ret = 0;
    const myst_verity_sb_t* sb = &dev->sb;
    const size_t hash_size = sb->salt_size;
    const size_t num_blocks = sb->data_blocks;
    const size_t digests_per_block = sb->hash_block_size / hash_size;
    const size_t blksz = sb->hash_block_size;
    struct level
    {
        size_t nnodes;
        size_t offset;
    };
    size_t nlevels = 0;
    size_t nchecks = 0;
    size_t total_nodes = 0;
    struct vars
    {
        struct level levels[32];
        block_t block;
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    /* count the number of nodes at every level of the hash tree */
    {
        size_t n = num_blocks;

        do
        {
            n = _next_multiple(n, digests_per_block);
            v->levels[nlevels++].nnodes = n;
        } while (n > 1);
    }

    /* calculate the offsets for each level */
    {
        size_t offset = 0;

        for (ssize_t i = (ssize_t)nlevels - 1; i >= 0; i--)
        {
            v->levels[i].offset = offset;
            offset += v->levels[i].nnodes;
        }
    }

    /* calculate the total number of nodes in the hash tree */
    for (size_t i = 0; i < nlevels; i++)
    {
        total_nodes += v->levels[i].nnodes;
#if 0
        printf(
              "levels(index=%zu, nnodes=%zu offset=%zu)\n",
              i,
              levels[i].nnodes,
              levels[i].offset);
#endif
    }

    /* read the hash blocks into memory (skip the superblock) */
    for (size_t i = 0; i < total_nodes; i++)
    {
        size_t blkno = i + 1;
        ECHECK(_read_hash_block(dev, blkno, &v->block));
        ECHECK(myst_buf_append(&dev->hashtree, &v->block, blksz));
    }

    /* save pointer to the start of the hash leaves */
    dev->leaves_start = dev->hashtree.data + (v->levels[0].offset * blksz);
    dev->leaves_end = dev->hashtree.data + dev->hashtree.size;

    /* verify the hash tree from the bottom up */
    for (size_t i = 0; i < nlevels; i++)
    {
        const size_t nnodes = v->levels[i].nnodes;
        const size_t offset = v->levels[i].offset;
        size_t parent = 0;
        const uint8_t* htree = dev->hashtree.data;
        const uint8_t* phash = NULL;

        /* set pointer to current parent hash */
        if (i + 1 != nlevels)
            phash = htree + (v->levels[i + 1].offset * blksz);

        for (size_t j = 0; j < nnodes; j++)
        {
            size_t index = j + offset;
            const void* data = htree + (index * blksz);
            myst_sha256_t hash;

            _hash2(dev->sb.salt, dev->sb.salt_size, data, blksz, &hash);

            /* find parent hash and see if it matched */
            if (phash)
            {
                if (memcmp(phash, &hash, sizeof(myst_sha256_t)) != 0)
                    ERAISE(-EIO);

                phash += sizeof(myst_sha256_t);
            }
            else if (memcmp(dev->roothash, &hash, dev->roothash_size) != 0)
            {
                ERAISE(-EIO);
            }

            /* count the number of hash verification checks performed */
            nchecks++;

            if (j > 0 && (j % digests_per_block) == 0)
                parent++;
        }
    }

    if (nchecks != total_nodes)
        ERAISE(-EIO);

done:

    if (v)
        free(v);

    return ret;
}

static int _close(myst_blkdev_t* dev_)
{
    int ret = 0;
    blkdev_t* dev = (blkdev_t*)dev_;

    if (!_blkdev_valid(dev))
        ERAISE(-EINVAL);

    myst_buf_release(&dev->hashtree);
    _release_cache(dev);
    free(dev);

done:
    return ret;
}

static int _get(myst_blkdev_t* dev_, size_t blkno, void* data)
{
    int ret = 0;
    blkdev_t* dev = (blkdev_t*)dev_;

    if (!_blkdev_valid(dev) || !data)
        ERAISE(-EINVAL);

    ECHECK(_get_raw_block(dev, blkno, data));

done:
    return ret;
}

static int _put(myst_blkdev_t* dev_, size_t blkno, const void* data)
{
    int ret = 0;
    blkdev_t* dev = (blkdev_t*)dev_;

    if (!_blkdev_valid(dev) || !data)
        ERAISE(-EINVAL);

    ECHECK(_put_raw_block(dev, blkno, data));

done:
    return ret;
}

int myst_verityblkdev_open(
    const char* path,
    size_t hash_offset,
    const uint8_t* roothash,
    size_t roothash_size,
    myst_blkdev_t** blkdev)
{
    int ret = 0;
    blkdev_t* dev = NULL;
    size_t first_hash_blkno = hash_offset / MYST_BLKSIZE;
    int rawblkdev = -1;
    struct vars
    {
        myst_verity_sb_t sb;
    };
    struct vars* v = NULL;

    if (blkdev)
        *blkdev = NULL;

    /* check parameters */
    if (!path || !roothash || !blkdev)
        ERAISE(-EINVAL);

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    if (roothash_size > MAX_ROOTHASH_SIZE)
        ERAISE(-EINVAL);

    ECHECK((rawblkdev = myst_open_block_device(path, true)));

    /* read the super block */
    {
        ECHECK(_read_superblock(rawblkdev, first_hash_blkno, &v->sb));

        /* only "normal" mode is supported (no Chrome OS) */
        if (v->sb.hash_type != 1)
            ERAISE(-ENOTSUP);

        /* only "sha256" is supported */
        if (strcmp(v->sb.algorithm, "sha256") != 0)
            ERAISE(-ENOTSUP);

        /* salt size (and hence hash size) must be 32 (sha256 hash size) */
        if (v->sb.salt_size != 32)
            ERAISE(-ENOTSUP);

        /* only supporting data block size of 4096 */
        if (v->sb.data_block_size != 4096)
            ERAISE(-ENOTSUP);

        /* only supporting hash block size of 4096 */
        if (v->sb.hash_block_size != 4096)
            ERAISE(-ENOTSUP);
    }

    /* allocate the new block device */
    if (!(dev = (blkdev_t*)calloc(1, sizeof(blkdev_t))))
        ERAISE(-ENOMEM);

    /* initialize the block device */
    dev->base.close = _close;
    dev->base.put = _put;
    dev->base.get = _get;
    dev->magic = VERITYBLKDEV_MAGIC;
    dev->first_hash_blkno = first_hash_blkno;
    dev->rawblkdev = rawblkdev;
    dev->max_cache_blocks = MAX_CACHE_BLOCKS;
    rawblkdev = -1;
    memcpy(&dev->sb, &v->sb, sizeof(myst_verity_sb_t));

    /* convert the roothash to binary */
    memcpy(dev->roothash, roothash, roothash_size);
    dev->roothash_size = roothash_size;

    /* fail if the root hash is not the same size as the salt */
    if (dev->roothash_size != v->sb.salt_size)
        ERAISE(-EINVAL);

    /* load the hash tree into memory */
    ECHECK(_load_hash_tree(dev));

    *blkdev = &dev->base;
    dev = NULL;

done:

    if (v)
        free(v);

    if (dev)
        free(dev);

    if (rawblkdev >= 0)
        myst_close_block_device(rawblkdev);

    return ret;
}
