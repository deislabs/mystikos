// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RAWBLKDEV_H
#define _MYST_RAWBLKDEV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct myst_block
{
    uint8_t data[512];
} myst_block_t;

int myst_open_block_device(const char* path, bool read_only);

int myst_close_block_device(int blkdev);

int myst_write_block_device(
    int blkdev,
    uint64_t blkno,
    const struct myst_block* blocks,
    size_t num_blocks);

int myst_read_block_device(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks);

#endif /* _MYST_RAWBLKDEV_H */
