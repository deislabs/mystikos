#include <myst/blockdevice.h>
#include "myst_u.h"

int myst_open_block_device_ocall(const char* path, bool read_only)
{
    return myst_open_block_device(path, read_only);
}

int myst_close_block_device_ocall(int blkdev)
{
    return myst_close_block_device(blkdev);
}

int myst_write_block_device_ocall(
    int blkdev,
    uint64_t blkno,
    const struct myst_block* blocks,
    size_t num_blocks)
{
    return myst_write_block_device(blkdev, blkno, blocks, num_blocks);
}

int myst_read_block_device_ocall(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks)
{
    return myst_read_block_device(blkdev, blkno, blocks, num_blocks);
}
