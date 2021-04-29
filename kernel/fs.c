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
#include <myst/process.h>
#include <myst/pubkey.h>
#include <myst/roothash.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/verity.h>

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

int myst_remove_fd_link(int fd)
{
    int ret = 0;
    struct vars
    {
        char path[PATH_MAX];
    };
    struct vars* v = NULL;
    const size_t n = sizeof(v->path);

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    if (snprintf(v->path, n, "/proc/%d/fd/%d", myst_getpid(), fd) >= (int)n)
        ERAISE(-ENAMETOOLONG);

    ECHECK(myst_syscall_unlink(v->path));

done:

    if (v)
        free(v);

    return ret;
}

#ifdef MYST_ENABLE_EXT2FS
int myst_load_fs(
    myst_mount_resolve_callback_t resolve_cb,
    const char* source,
    const char* key,
    myst_fs_t** fs_out)
{
    int ret = 0;
    myst_blkdev_t* blkdev = NULL;
    myst_fs_t* fs = NULL;
    int r;
    struct vars
    {
        myst_fssig_t fssig;
        uint8_t keybuf[1024];
    };
    struct vars* v = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (!source)
        ERAISE(-EINVAL);

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    /* load the file-system signature structure */
    if ((r = myst_tcall_load_fssig(source, &v->fssig)) != 0 && r != -ENOTSUP)
        ERAISE(-r);

    /* create the bottom device (verity or raw) */
    if (v->fssig.magic == MYST_FSSIG_MAGIC)
    {
        if (v->fssig.signature_size)
        {
            ECHECK(myst_pubkey_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                v->fssig.root_hash,
                sizeof(v->fssig.root_hash),
                v->fssig.signer,
                sizeof(v->fssig.signer),
                v->fssig.signature,
                v->fssig.signature_size));
        }
        else
        {
            ECHECK(myst_roothash_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                v->fssig.root_hash,
                sizeof(v->fssig.root_hash)));
        }

        /* create the device stack */
        ECHECK(myst_verityblkdev_open(
            source,
            v->fssig.hash_offset,
            v->fssig.root_hash,
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
        ssize_t keysize;
        myst_blkdev_t* tmp;

        /* convert key from hex-ASCII to binary */
        ECHECK(
            (keysize = myst_ascii_to_bin(key, v->keybuf, sizeof(v->keybuf))));

        ECHECK(myst_luksblkdev_open(blkdev, v->keybuf, keysize, &tmp));
        blkdev = tmp;
    }

    ECHECK(ext2_create(blkdev, &fs, resolve_cb));
    blkdev = NULL;

    *fs_out = fs;
    fs = NULL;

done:

    if (v)
        free(v);

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
