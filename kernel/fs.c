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
#include <myst/lockfs.h>
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
    struct locals
    {
        char path[PATH_MAX];
    };
    struct locals* locals = NULL;
    const size_t n = sizeof(locals->path);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (snprintf(locals->path, n, "/proc/%d/fd/%d", myst_getpid(), fd) >=
        (int)n)
        ERAISE(-ENAMETOOLONG);

    ECHECK(myst_syscall_unlink(locals->path));

done:

    if (locals)
        free(locals);

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
    myst_fs_t* ext2fs = NULL;
    int r;
    struct locals
    {
        myst_fssig_t fssig;
        uint8_t keybuf[1024];
    };
    struct locals* locals = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (!source)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* load the file-system signature structure */
    if ((r = myst_tcall_load_fssig(source, &locals->fssig)) != 0 &&
        r != -ENOTSUP)
        ERAISE(-r);

    /* create the bottom device (verity or raw) */
    if (locals->fssig.magic == MYST_FSSIG_MAGIC)
    {
        if (locals->fssig.signature_size)
        {
            ECHECK(myst_pubkey_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                locals->fssig.root_hash,
                sizeof(locals->fssig.root_hash),
                locals->fssig.signer,
                sizeof(locals->fssig.signer),
                locals->fssig.signature,
                locals->fssig.signature_size));
        }
        else
        {
            ECHECK(myst_roothash_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                locals->fssig.root_hash,
                sizeof(locals->fssig.root_hash)));
        }

        /* create the device stack */
        ECHECK(myst_verityblkdev_open(
            source,
            locals->fssig.hash_offset,
            locals->fssig.root_hash,
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
            (keysize = myst_ascii_to_bin(
                 key, locals->keybuf, sizeof(locals->keybuf))));

        ECHECK(myst_luksblkdev_open(blkdev, locals->keybuf, keysize, &tmp));
        blkdev = tmp;
    }

    /* wrap ext2fs inside a lockfs */
    ECHECK(ext2_create(blkdev, &ext2fs, resolve_cb));
    ECHECK(myst_lockfs_init(ext2fs, &fs));
    ext2fs = NULL;

    blkdev = NULL;
    *fs_out = fs;
    fs = NULL;

done:

    if (locals)
        free(locals);

    if (blkdev)
        (blkdev->close)(blkdev);

    if (fs)
        (fs->fs_release)(fs);

    if (ext2fs)
        (ext2fs->fs_release)(ext2fs);

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
