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
    char* path = NULL;
    const size_t n = sizeof(path);

    if (asprintf(&path, "/proc/%d/fd/%d", myst_getpid(), fd) >= (int)n)
        ERAISE(-ENAMETOOLONG);

    ECHECK(myst_syscall_unlink(path));

done:

    if (path)
        free(path);

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
    myst_fssig_t* fssig = NULL;
    int r;
    uint8_t* keybuf = NULL;
    const size_t keybuf_size = 1024;

    if (fs_out)
        *fs_out = NULL;

    if (!source)
        ERAISE(-EINVAL);

    if (!(fssig = malloc(sizeof(myst_fssig_t))))
        ERAISE(-ENOMEM);

    /* load the file-system signature structure */
    if ((r = myst_tcall_load_fssig(source, fssig)) != 0 && r != -ENOTSUP)
        ERAISE(-r);

    /* create the bottom device (verity or raw) */
    if (fssig->magic == MYST_FSSIG_MAGIC)
    {
        if (fssig->signature_size)
        {
            ECHECK(myst_pubkey_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                fssig->root_hash,
                sizeof(fssig->root_hash),
                fssig->signer,
                sizeof(fssig->signer),
                fssig->signature,
                fssig->signature_size));
        }
        else
        {
            ECHECK(myst_roothash_verify(
                __myst_kernel_args.archive_data,
                __myst_kernel_args.archive_size,
                fssig->root_hash,
                sizeof(fssig->root_hash)));
        }

        /* create the device stack */
        ECHECK(myst_verityblkdev_open(
            source,
            fssig->hash_offset,
            fssig->root_hash,
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

        if (!(keybuf = malloc(keybuf_size)))
            ERAISE(-EINVAL);

        /* convert key from hex-ASCII to binary */
        ECHECK((keysize = myst_ascii_to_bin(key, keybuf, keybuf_size)));

        ECHECK(myst_luksblkdev_open(blkdev, keybuf, keysize, &tmp));
        blkdev = tmp;
    }

    ECHECK(ext2_create(blkdev, &fs, resolve_cb));
    blkdev = NULL;

    *fs_out = fs;
    fs = NULL;

done:

    if (blkdev)
        (blkdev->close)(blkdev);

    if (fs)
        (fs->fs_release)(fs);

    if (fssig)
        free(fssig);

    if (keybuf)
        free(keybuf);

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

int myst_fs_realpath(myst_fs_t* fs, myst_file_t* file, char** buf_out)
{
    int ret = 0;
    char* buf = NULL;

    if (buf_out)
        *buf_out = NULL;

    if (!(buf = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK((*fs->fs_realpath)(fs, file, buf, PATH_MAX));
    *buf_out = buf;
    buf = NULL;

done:

    if (buf)
        free(buf);

    return ret;
}
