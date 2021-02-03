// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <myst/blkdev.h>
#include <myst/byteorder.h>
#include <myst/eraise.h>
#include <myst/luks.h>

// clang-format off
#define LUKS_MAGIC_INITIALIZER { 'L', 'U', 'K', 'S', 0xba, 0xbe }
// clang-format oon

#define LUKSBLKDEV_MAGIC 0x5acdeed9

_Static_assert(MYST_BLKSIZE == LUKS_SECTOR_SIZE, "");

typedef struct blkdev
{
    myst_blkdev_t base;
    uint32_t magic;
    luks_phdr_t phdr;
    myst_blkdev_t* rawdev;   /* underlying raw LUKS device */
    uint8_t* masterkey; /* size given by phdr->key_bytes */
}
blkdev_t;

static bool _luksblkdev_valid(blkdev_t* dev)
{
    return dev != NULL && dev->magic == LUKSBLKDEV_MAGIC;
}

static int _close(myst_blkdev_t* dev_)
{
    int ret = 0;
    blkdev_t* dev = (blkdev_t*)dev_;

    if (!_luksblkdev_valid(dev))
        ERAISE(-EINVAL);

    if (dev->masterkey)
        free(dev->masterkey);

    if (dev->rawdev)
        dev->rawdev->close(dev->rawdev);

    free(dev);

done:
    return ret;
}

static int _get(myst_blkdev_t* dev_, size_t blkno, void* data)
{
    int ret = 0;
    blkdev_t* dev = (blkdev_t*)dev_;
    uint8_t buf[LUKS_SECTOR_SIZE];

    if (!_luksblkdev_valid(dev) || !data)
        ERAISE(-EINVAL);

    /* read the encrypted sector */
    myst_blkdev_t* rawdev = dev->rawdev;
    ECHECK((*rawdev->get)(rawdev, blkno + dev->phdr.payload_offset, buf));

    /* decrypt the sector with the master key */
    if (myst_luks_decrypt(
        &dev->phdr,
        dev->masterkey,
        buf,
        data,
        LUKS_SECTOR_SIZE,
        blkno) != 0)
    {
        ERAISE(-EIO);
    }

done:
    return ret;
}

static int _put(myst_blkdev_t* dev_, size_t blkno, const void* data)
{
    int ret = 0;
    blkdev_t* dev = (blkdev_t*)dev_;
    uint8_t buf[LUKS_SECTOR_SIZE];

    if (!_luksblkdev_valid(dev) || !data)
        ERAISE(-EINVAL);

    /* encrypt the sector with the master key */
    if (myst_luks_encrypt(
        &dev->phdr,
        dev->masterkey,
        data,
        buf,
        LUKS_SECTOR_SIZE,
        blkno) != 0)
    {
        ERAISE(-EIO);
    }

    /* write the encrypted sector */
    myst_blkdev_t* rawdev = dev->rawdev;
    ECHECK((*rawdev->put)(rawdev, blkno + dev->phdr.payload_offset, buf));

done:
    return ret;
}

static void _fix_phdr_byte_order(luks_phdr_t* phdr)
{
    if (!myst_is_big_endian())
    {
        phdr->version = myst_swap_u16(phdr->version);
        phdr->payload_offset = myst_swap_u32(phdr->payload_offset);
        phdr->key_bytes = myst_swap_u32(phdr->key_bytes);
        phdr->mk_digest_iter = myst_swap_u32(phdr->mk_digest_iter);

        for (size_t i = 0; i < LUKS_SLOTS_SIZE; i++)
        {
            luks_keyslot_t* p = &phdr->slots[i];
            p->active = myst_swap_u32(p->active);
            p->iterations = myst_swap_u32(p->iterations);
            p->key_material_offset = myst_swap_u32(p->key_material_offset);
            p->stripes = myst_swap_u32(p->stripes);
        }
    }
}

static int _read_phdr(myst_blkdev_t* rawdev, luks_phdr_t* phdr)
{
    int ret = 0;
    union {
        luks_phdr_t phdr;
        uint8_t sectors[2*LUKS_SECTOR_SIZE];
    } u;
    static uint8_t _magic[] = LUKS_MAGIC_INITIALIZER;

    if (!rawdev)
        ERAISE(-EINVAL);

    /* read the first two sectors of the raw devices */
    ECHECK((rawdev->get)(rawdev, 0, &u.sectors[0]));
    ECHECK((rawdev->get)(rawdev, 0, &u.sectors[LUKS_SECTOR_SIZE]));

    /* check the LUKS magic bytes */
    if (memcmp(u.phdr.magic, _magic, LUKS_MAGIC_SIZE) != 0)
        ERAISE(-EINVAL);

    if (phdr)
    {
        memcpy(phdr, &u.phdr, sizeof(luks_phdr_t));
        _fix_phdr_byte_order(phdr);
    }

done:
    return ret;
}

int myst_luksblkdev_open(
    myst_blkdev_t* rawdev,
    const uint8_t* masterkey,
    uint32_t masterkey_bytes,
    myst_blkdev_t** blkdev)
{
    int ret = 0;
    blkdev_t* dev = NULL;
    uint8_t* mk = NULL;
    luks_phdr_t phdr;

    if (blkdev)
        *blkdev = NULL;

    /* check parameters */
    if (!rawdev || !masterkey || !blkdev)
        ERAISE(-EINVAL);

    /* read the LUKS phdr */
    ECHECK(_read_phdr(rawdev, &phdr));

    /* if masterkey size is wrong */
    if (masterkey_bytes != phdr.key_bytes)
        ERAISE(-EINVAL);

    /* allocate the master key */
    if (!(mk = (uint8_t*)calloc(1, phdr.key_bytes)))
        ERAISE(-ENOMEM);

    /* clone the master key */
    memcpy(mk, masterkey, phdr.key_bytes);

    /* allocate the block device */
    if (!(dev = (blkdev_t*)calloc(1, sizeof(blkdev_t))))
        ERAISE(-ENOMEM);

    /* initialize the block device */
    dev->base.close = _close;
    dev->base.put = _put;
    dev->base.get = _get;
    dev->rawdev = rawdev;
    dev->magic = LUKSBLKDEV_MAGIC;
    dev->phdr = phdr;
    dev->masterkey = mk;

    *blkdev = &dev->base;
    dev = NULL;
    mk = NULL;

done:

    if (dev)
        free(dev);

    if (mk)
        free(mk);

    return ret;
}

int myst_luksblkdev_check_phdr(myst_blkdev_t* rawdev)
{
    return _read_phdr(rawdev, NULL);
}
