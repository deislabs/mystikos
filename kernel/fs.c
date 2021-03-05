// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <limits.h>

#include <myst/blkdev.h>
#include <myst/eraise.h>
#include <myst/ext2.h>
#include <myst/fs.h>
#include <myst/fssig.h>
#include <myst/hex.h>
#include <myst/kernel.h>
#include <myst/mount.h>
#include <myst/pubkey.h>
#include <myst/roothash.h>
#include <myst/tcall.h>
#include <myst/verity.h>
#include <myst/thread.h>

const char* myst_fstype_name(myst_fstype_t fstype)
{
    switch (fstype)
    {
        case MYST_FSTYPE_NONE:
            return "NONE";
        case MYST_FSTYPE_RAMFS:
            return "RAMFS";
        case MYST_FSTYPE_EXT2FS:
            return "EXT2FS";
        case MYST_FSTYPE_HOSTFS:
            return "HOSTFS";
    }

    return "NONE";
}

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

#ifdef MYST_ENABLE_EXT2FS
int myst_load_fs(const char* source, const char* key, myst_fs_t** fs_out)
{
    int ret = 0;
    myst_blkdev_t* blkdev = NULL;
    myst_fs_t* fs = NULL;
    myst_fssig_t fssig;
    int r;

    if (fs_out)
        *fs_out = NULL;

    if (!source)
        ERAISE(-EINVAL);

    /* load the file-system signature structure */
    if ((r = myst_tcall_load_fssig(source, &fssig)) != 0 && r != -ENOTSUP)
        ERAISE(-r);

    /* create the bottom device (verity or raw) */
    if (fssig.magic == MYST_FSSIG_MAGIC)
    {
        if (fssig.signature_size)
        {
            ECHECK(myst_pubkey_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                fssig.root_hash,
                sizeof(fssig.root_hash),
                fssig.signer,
                sizeof(fssig.signer),
                fssig.signature,
                fssig.signature_size));
        }
        else
        {
            ECHECK(myst_roothash_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                fssig.root_hash,
                sizeof(fssig.root_hash)));
        }

        /* create the device stack */
        ECHECK(myst_verityblkdev_open(
            source,
            fssig.hash_offset,
            fssig.root_hash,
            sizeof(myst_sha256_t),
            &blkdev));
    }
    else
    {
        const bool ephemeral = true;
        ECHECK(myst_rawblkdev_open(source, ephemeral, 0, &blkdev));
    }

    if (key)
    {
        uint8_t keybuf[1024];
        ssize_t keysize;
        myst_blkdev_t* tmp;

        /* convert key from hex-ASCII to binary */
        ECHECK((keysize = myst_ascii_to_bin(key, keybuf, sizeof(keybuf))));

        ECHECK(myst_luksblkdev_open(blkdev, keybuf, keysize, &tmp));
        blkdev = tmp;
    }

    ECHECK(ext2_create(blkdev, &fs));
    blkdev = NULL;

    *fs_out = fs;
    fs = NULL;

done:

    if (blkdev)
        (blkdev->close)(blkdev);

    if (fs)
        (fs->fs_release)(fs);

    return ret;
}
#endif /* MYST_ENABLE_EXT2FS */

long myst_syscall_umask(mode_t mask)
{
    long ret;
    myst_thread_t* process;

    if (!(process = myst_find_process_thread(myst_thread_self())))
        ERAISE(-EINVAL);

    myst_spin_lock(&process->main.umask_lock);
    ret = process->main.umask;
    process->main.umask = mask;
    myst_spin_unlock(&process->main.umask_lock);

done:
    return ret;
}
