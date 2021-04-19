// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <myst/atexit.h>
#include <myst/blkdev.h>
#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/ext2.h>
#include <myst/fssig.h>
#include <myst/hex.h>
#include <myst/hostfs.h>
#include <myst/kernel.h>
#include <myst/mount.h>
#include <myst/pubkey.h>
#include <myst/ramfs.h>
#include <myst/realpath.h>
#include <myst/roothash.h>
#include <myst/sha256.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/verity.h>

#define MOUNT_TABLE_SIZE 8

typedef struct mount_table_entry
{
    char* path;
    size_t path_size;
    myst_fs_t* fs;
    uint32_t flags;
} mount_table_entry_t;

static mount_table_entry_t _mount_table[MOUNT_TABLE_SIZE];
static size_t _mount_table_size = 0;
static myst_spinlock_t _lock = MYST_SPINLOCK_INITIALIZER;

static bool _installed_free_mount_table = false;

static void _free_mount_table(void* arg)
{
    (void)arg;

    for (size_t i = 0; i < _mount_table_size; i++)
        free(_mount_table[i].path);
}

int myst_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    myst_fs_t** fs_out)
{
    int ret = 0;
    size_t match_len = 0;
    bool locked = false;
    myst_fs_t* fs = NULL;
    typedef struct _variables
    {
        myst_path_t realpath;
    } variables_t;
    variables_t* v = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (!path || !suffix)
        ERAISE(-EINVAL);

    if (!(v = calloc(1, sizeof(variables_t))))
        ERAISE(-ENOMEM);

    /* Find the real path (the absolute non-relative path). */
    ECHECK(myst_realpath(path, &v->realpath));

    myst_spin_lock(&_lock);
    locked = true;

    /* Find the longest binding point that contains this path. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        size_t len = strlen(_mount_table[i].path);
        const char* mpath = _mount_table[i].path;

        if (mpath[0] == '/' && mpath[1] == '\0')
        {
            if (len > match_len)
            {
                myst_strlcpy(suffix, v->realpath.buf, PATH_MAX);
                match_len = len;
                fs = _mount_table[i].fs;
            }
        }
        else if (
            strncmp(mpath, v->realpath.buf, len) == 0 &&
            (v->realpath.buf[len] == '/' || v->realpath.buf[len] == '\0'))
        {
            if (len > match_len)
            {
                myst_strlcpy(suffix, v->realpath.buf + len, PATH_MAX);

                if (*suffix == '\0')
                    myst_strlcpy(suffix, "/", PATH_MAX);

                match_len = len;
                fs = _mount_table[i].fs;
            }
        }
    }

    if (locked)
    {
        myst_spin_unlock(&_lock);
        locked = false;
    }

    if (!fs)
        ERAISE(-ENOENT);

    *fs_out = fs;

done:

    if (locked)
        myst_spin_unlock(&_lock);

    if (v)
        free(v);

    return ret;
}

int myst_mount_resolve2(const char* path, char** suffix_out, myst_fs_t** fs_out)
{
    int ret = 0;
    char* suffix = NULL;

    if (!(suffix = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(path, suffix, fs_out));
    *suffix_out = suffix;
    suffix = NULL;

done:

    if (suffix)
        free(suffix);

    return ret;
}

int myst_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = -1;
    bool locked = false;
    typedef struct _variables
    {
        myst_path_t target_buf;
        mount_table_entry_t mount_table_entry;
        struct stat buf;
        char suffix[PATH_MAX];
    } variables_t;
    variables_t* v = NULL;

    if (!fs || !source || !target)
        ERAISE(-EINVAL);

    if (!(v = calloc(1, sizeof(variables_t))))
        ERAISE(-ENOMEM);

    /* Normalize the target path */
    {
        ECHECK(myst_realpath(target, &v->target_buf));
        target = v->target_buf.buf;
    }

    /* Be sure the target directory exists (if not root) */
    if (strcmp(target, "/") != 0)
    {
        myst_fs_t* parent;

        /* Find the file system onto which the mount will occur */
        ECHECK(myst_mount_resolve(target, v->suffix, &parent));

        ECHECK((*parent->fs_stat)(parent, target, &v->buf));

        if (!S_ISDIR(v->buf.st_mode))
            ERAISE(-ENOTDIR);
    }

    /* Lock the mount table. */
    myst_spin_lock(&_lock);
    locked = true;

    /* Install _free_mount_table() if not already installed. */
    if (_installed_free_mount_table == false)
    {
        myst_atexit(_free_mount_table, NULL);
        _installed_free_mount_table = true;
    }

    /* Fail if mount table exhausted. */
    if (_mount_table_size == MOUNT_TABLE_SIZE)
        ERAISE(-ENOMEM);

    /* Reject duplicate mount paths. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        if (strcmp(_mount_table[i].path, target) == 0)
            ERAISE(-EEXIST);
    }

    /* Tell the file system that it has been mounted */
    ECHECK((*fs->fs_mount)(fs, source, target));

    /* Assign and initialize new mount point. */
    {
        if (!(v->mount_table_entry.path = strdup(target)))
            ERAISE(-ENOMEM);

        v->mount_table_entry.path_size = strlen(target) + 1;
        v->mount_table_entry.fs = fs;
        v->mount_table_entry.flags = 0;
    }

    _mount_table[_mount_table_size++] = v->mount_table_entry;
    v->mount_table_entry.path = NULL;

    ret = 0;

done:

    if (v->mount_table_entry.path)
        free(v->mount_table_entry.path);

    if (locked)
        myst_spin_unlock(&_lock);

    if (v)
        free(v);

    return ret;
}

int myst_umount(const char* target)
{
    int ret = 0;
    bool found = false;
    typedef struct _variables
    {
        myst_path_t realpath;
    } variables_t;
    variables_t* v = NULL;

    if (!(v = calloc(1, sizeof(variables_t))))
        ERAISE(-ENOMEM);

    myst_spin_lock(&_lock);

    /* Find the real path (the absolute non-relative path) */
    ECHECK(myst_realpath(target, &v->realpath));

    /* search the mount table for an entry with this name */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        mount_table_entry_t* entry = &_mount_table[i];

        if (strcmp(entry->path, v->realpath.buf) == 0)
        {
            /* release the path */
            free(entry->path);

            /* release the file system */
            ECHECK((*entry->fs->fs_release)(entry->fs));

            /* remove this entry from the mount table */
            _mount_table[i] = _mount_table[_mount_table_size - 1];
            _mount_table_size--;

            found = true;
            break;
        }
    }

    if (!found)
        ERAISE(-ENOENT);

done:

    myst_spin_unlock(&_lock);

    if (v)
        free(v);

    return ret;
}

#ifdef MYST_ENABLE_EXT2FS
static const char* _find_arg(const char* args[], const char* name)
{
    if (!args)
        return NULL;

    for (size_t i = 0; args[i]; i += 2)
    {
        if (!args[i + 1])
            return NULL;

        if (strcmp(args[i], name) == 0)
            return args[i + 1];
    }

    /* not found */
    return NULL;
}
#endif /* MYST_ENABLE_EXT2FS */

long myst_syscall_mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data)
{
    long ret = 0;
    myst_fs_t* fs = NULL;
    myst_blkdev_t* blkdev = NULL;

    if (!source || !target || !filesystemtype)
        ERAISE(-EINVAL);

    if (strcmp(filesystemtype, "ramfs") == 0)
    {
        /* these arguments should be zero and null */
        if (mountflags || data)
            ERAISE(-EINVAL);

        /* create a new ramfs instance */
        ECHECK(myst_init_ramfs(myst_mount_resolve, &fs));

        /* perform the mount */
        ECHECK(myst_mount(fs, source, target));
        fs = NULL;

        /* load the rootfs */
        ECHECK(myst_cpio_unpack(source, target));
    }
#ifdef MYST_ENABLE_HOSTFS
    else if (strcmp(filesystemtype, "hostfs") == 0)
    {
        /* these arguments should be zero and null */
        if (mountflags || data)
            ERAISE(-EINVAL);

        /* create a new ramfs instance */
        ECHECK(myst_init_hostfs(&fs));

        /* perform the mount */
        ECHECK(myst_mount(fs, source, target));
        fs = NULL;
    }
#endif /* MYST_ENABLE_HOSTFS */
#ifdef MYST_ENABLE_EXT2FS
    else if (strcmp(filesystemtype, "ext2") == 0)
    {
        const char** args = (const char**)data;
        const char* key;

        if (mountflags || !source)
            ERAISE(-EINVAL);

        key = _find_arg(args, "key");

        ECHECK(myst_load_fs(myst_mount_resolve, source, key, &fs));

        /* perform the mount */
        ECHECK(myst_mount(fs, source, target));
        fs = NULL;
    }
#endif /* MYST_ENABLE_EXT2FS */
    else
    {
        ERAISE(-ENOTSUP);
    }

done:

    if (blkdev)
        (blkdev->close)(blkdev);

    if (fs)
        (fs->fs_release)(fs);

    return ret;
}

long myst_syscall_umount2(const char* target, int flags)
{
    long ret = 0;

    if (!target || flags != 0)
        ERAISE(-EINVAL);

    ECHECK(myst_umount(target));

done:
    return ret;
}
