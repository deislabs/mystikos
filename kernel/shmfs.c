// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/mount.h>
#include <myst/printf.h>
#include <myst/ramfs.h>
#include <myst/shmfs.h>

static myst_fs_t* _shmfs;

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
