// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BLKDEV_H
#define _MYST_BLKDEV_H

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define MYST_BLKSIZE 512

typedef struct myst_blkdev myst_blkdev_t;

struct myst_blkdev
{
    int (*close)(myst_blkdev_t* dev);

    int (*get)(myst_blkdev_t* dev, uint64_t blkno, void* data);

    int (*put)(myst_blkdev_t* dev, uint64_t blkno, const void* data);
};

int myst_rawblkdev_open(
    const char* path,
    bool ephemeral,
    uint64_t blkno_offset, /* add to blkno to obtain the raw block number */
    myst_blkdev_t** dev);

int myst_luksblkdev_open(
    myst_blkdev_t* rawdev,
    const uint8_t* masterkey,
    uint32_t masterkey_bytes,
    myst_blkdev_t** blkdev);

int myst_luksblkdev_check_phdr(myst_blkdev_t* rawdev);

int myst_verityblkdev_open(
    const char* path,
    size_t hash_offset,
    const uint8_t* roothash,
    size_t roothash_size,
    myst_blkdev_t** blkdev);

#endif /* _MYST_BLKDEV_H */
