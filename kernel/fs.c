// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <limits.h>

#include <myst/eraise.h>
#include <myst/fs.h>
#include <myst/mount.h>

int myst_remove_fd_link(myst_fs_t* fs, myst_file_t* file, int fd)
{
    int ret = 0;
    char linkpath[PATH_MAX];
    const size_t n = sizeof(linkpath);
    char realpath[PATH_MAX];

    if (!fs || fd < 0)
        ERAISE(-EINVAL);

    ECHECK((*fs->fs_realpath)(fs, file, realpath, sizeof(realpath)));

    if (snprintf(linkpath, n, "/proc/self/fd/%d", fd) >= (int)n)
        ERAISE(-ENAMETOOLONG);

    /* only the root file system can remove the link path */
    {
        char suffix[PATH_MAX];
        myst_fs_t* rootfs;

        ECHECK(myst_mount_resolve("/", suffix, &rootfs));

        ECHECK((*rootfs->fs_unlink)(rootfs, linkpath));
    }

done:
    return ret;
}
