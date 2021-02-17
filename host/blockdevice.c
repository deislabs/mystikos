// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <myst/blockdevice.h>
#include <myst/eraise.h>
#include "strings.h"

static ssize_t _readn(int fd, void* data, size_t size, off_t off)
{
    ssize_t ret = 0;
    unsigned char* p = (unsigned char*)data;
    size_t r = size;

    while (r)
    {
        ssize_t n = pread(fd, p, r, off);

        if (n > 0)
        {
            p += n;
            r -= n;
            off += n;
        }
        else if (n == 0)
        {
            ERAISE(-EIO);
        }
        else
        {
            ERAISE(-errno);
        }
    }

    ret = size;

done:
    return ret;
}

static ssize_t _writen(int fd, const void* data, size_t size, off_t off)
{
    ssize_t ret = 0;
    const unsigned char* p = (const unsigned char*)data;
    size_t r = size;

    while (r)
    {
        ssize_t n = pwrite(fd, p, r, off);

        if (n > 0)
        {
            p += n;
            r -= n;
            off += n;
        }
        else if (n == 0)
        {
            ERAISE(-EIO);
        }
        else
        {
            ERAISE(-errno);
        }
    }

    ret = size;

done:
    return ret;
}

int myst_open_block_device(const char* path, bool read_only)
{
    int ret = 0;
    int blkdev;
    int flags = read_only ? O_RDONLY : O_RDWR;

    if ((blkdev = open(path, flags)) < 0)
        ERAISE(-errno);

    ret = blkdev;

done:
    return ret;
}

int myst_close_block_device(int blkdev)
{
    int ret = 0;

    if (blkdev < 0)
        ERAISE(-EINVAL);

    if (close(blkdev) != 0)
        ERAISE(-errno);

done:
    return ret;
}

int myst_write_block_device(
    int blkdev,
    uint64_t blkno,
    const struct myst_block* blocks,
    size_t num_blocks)
{
    int ret = 0;
    off_t offset = blkno * sizeof(myst_block_t);
    size_t size = num_blocks * sizeof(myst_block_t);

    if (blkdev < 0 || !blocks || num_blocks == 0)
        ERAISE(-EINVAL);

    if (_writen(blkdev, blocks, size, offset) != size)
        ERAISE(-EIO);

done:
    return ret;
}

int myst_read_block_device(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks)
{
    int ret = 0;
    off_t offset = blkno * sizeof(myst_block_t);
    size_t size = num_blocks * sizeof(myst_block_t);

    if (blkdev < 0 || !blocks || num_blocks == 0)
        ERAISE(-EINVAL);

    if (_readn(blkdev, blocks, size, offset) != size)
        ERAISE(-EIO);

done:
    return ret;
}
