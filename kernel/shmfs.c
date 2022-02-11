// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/mount.h>
#include <myst/printf.h>
#include <myst/ramfs.h>
#include <myst/shmfs.h>

static myst_fs_t* _shmfs;

/**
 * POSIX Shared Memory
 *
 * Leverage ramfs to implement POSIX Shared Memory semantics.
 *
 * Simple usage example:
 *
 * int fd = shm_open("foo", O_CREAT|O_RDWR , (S_IRUSR|S_IWUSR));
 * ftruncate(fd, SHM_SIZE);
 * char *addr = mmap(0, SHM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
 *
 * For mmap's related to files opened via shm_open, pointer to the underlying
 * file buffer is returned. ramfs files use myst_buf_t to store the data.
 *
 * Because a pointer to myst_buf_t is passed to the userspace, buffer resize
 * operations can be supported safely only when there are no active mappings
 * against the corresponding shmfs file.
 *
 */
int shmfs_setup()
{
    int ret = 0;

    if (myst_init_ramfs(myst_mount_resolve, &_shmfs, 9) != 0)
    {
        myst_eprintf("failed initialize the shm file system\n");
        ERAISE(-EINVAL);
    }

    ECHECK(set_overrides_for_special_fs(_shmfs));

    if (mkdir("/dev/shm", 0777) != 0)
    {
        myst_eprintf("cannot create mount point for shmfs\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_shmfs, "/", "/dev/shm", false) != 0)
    {
        myst_eprintf("cannot mount shm file system\n");
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

int shmfs_teardown()
{
    if ((*_shmfs->fs_release)(_shmfs) != 0)
    {
        myst_eprintf("failed to release shmfs\n");
        return -1;
    }

    return 0;
}
