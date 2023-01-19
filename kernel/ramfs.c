// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <myst/backtrace.h>
#include <myst/buf.h>
#include <myst/bufu64.h>
#include <myst/clock.h>
#include <myst/devfs.h>
#include <myst/eraise.h>
#include <myst/fs.h>
#include <myst/id.h>
#include <myst/lockfs.h>
#include <myst/panic.h>
#include <myst/paths.h>
#include <myst/printf.h>
#include <myst/ramfs.h>
#include <myst/realpath.h>
#include <myst/round.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/syslog.h>
#include <myst/thread.h>
#include <myst/trace.h>
#include <myst/uid_gid.h>

#define BLKSIZE 512

/* ATTN: check access for all read operations */
/* ATTN: add whole-file-system locking */

/*
**==============================================================================
**
** ramfs_t:
**
**==============================================================================
*/

#define RAMFS_MAGIC 0x28F21778D1E711EA

typedef struct inode inode_t;

typedef struct ramfs
{
    myst_fs_t base;
    uint64_t magic;
    inode_t* root;
    char source[PATH_MAX]; /* source argument to myst_mount() */
    char target[PATH_MAX]; /* target argument to myst_mount() */
    myst_mount_resolve_callback_t resolve;
    size_t ninodes;
    myst_fs_t* lockfs;
    ramfs_minor_num_t device_num;
} ramfs_t;

static bool _ramfs_valid(const ramfs_t* ramfs)
{
    return ramfs && ramfs->magic == RAMFS_MAGIC;
}

static bool _is_shmfs(const ramfs_t* ramfs)
{
    return ramfs && ramfs->device_num == RAMFS_SHMFS;
}

/*
**==============================================================================
**
** inode_t
**
**==============================================================================
*/

#define INODE_MAGIC 0xcdfbdd61258a4c9d

struct inode
{
    uint64_t magic;
    uint32_t mode;         /* Type and mode */
    struct timespec atime; /* time of last access */
    struct timespec ctime; /* time of last metadata change */
    struct timespec mtime; /* time of last modification */
    size_t nlink;          /* number of hard links to this inode */
    size_t nopens;         /* number of times file is currently opened */
    myst_buf_t buf;        /* file or directory data */
    const void* data;      /* set by myst_ramfs_set_buf() */
    uid_t uid;             /* user ID who created */
    gid_t gid;             /* group ID who created */
    myst_vcallback_t v_cb; /* callback(s) for virtual files */
};

#define ACCESS 1
#define CHANGE 2
#define MODIFY 4

static bool _inode_valid(const inode_t* inode)
{
    return inode && inode->magic == INODE_MAGIC;
}

static bool _is_virtual_inode(const inode_t* inode)
{
    return inode && (inode->v_cb.open_cb || inode->v_cb.close_cb ||
                     inode->v_cb.read_cb || inode->v_cb.write_cb);
}

static void _update_timestamps(inode_t* inode, int flags)
{
    struct timespec ts;

    assert(_inode_valid(inode));

    if (myst_syscall_clock_gettime(CLOCK_REALTIME, &ts) != 0)
        myst_panic("clock_gettime() failed");

    if (flags & ACCESS)
        inode->atime = ts;

    if (flags & CHANGE)
        inode->ctime = ts;

    if (flags & MODIFY)
        inode->mtime = ts;
}

static void _inode_free(ramfs_t* ramfs, inode_t* inode)
{
    if (inode)
    {
        if (inode->buf.data != inode->data)
            myst_buf_release(&inode->buf);
        memset(inode, 0xdd, sizeof(inode_t));
        free(inode);

        ramfs->ninodes--;
    }
}

static int _split_path(
    const char* path,
    char dirname[PATH_MAX],
    char basename[PATH_MAX])
{
    return myst_split_path(path, dirname, PATH_MAX, basename, PATH_MAX);
}

/* Note: does not update nlink */
static int _inode_add_dirent(
    inode_t* dir,
    inode_t* inode,
    uint8_t type, /* DT_REG or DT_DIR */
    const char* name)
{
    int ret = 0;
    struct locals
    {
        struct dirent ent;
    };
    struct locals* locals = NULL;

    if (!_inode_valid(dir) || !_inode_valid(inode) || !name)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (type != DT_REG && type != DT_DIR && type != DT_LNK)
        ERAISE(-EINVAL);

    /* Append the new directory entry */
    {
        memset(&locals->ent, 0, sizeof(locals->ent));
        locals->ent.d_ino = (ino_t)inode;
        locals->ent.d_off = (off_t)dir->buf.size;
        locals->ent.d_reclen = sizeof(struct dirent);
        locals->ent.d_type = type;

        if (MYST_STRLCPY(locals->ent.d_name, name) >=
            sizeof(locals->ent.d_name))
            ERAISE(-ENAMETOOLONG);

        if (myst_buf_append(&dir->buf, &locals->ent, sizeof(locals->ent)) != 0)
            ERAISE(-ENOMEM);
    }

    _update_timestamps(dir, CHANGE | MODIFY);

done:

    if (locals)
        free(locals);

    return ret;
}

static bool _inode_is_empty_dir(const inode_t* inode)
{
    /* empty directories have two entries: "." and ".." */
    const size_t empty_size = (2 * sizeof(struct dirent));
    return inode && S_ISDIR(inode->mode) && inode->buf.size == empty_size;
}

#if 0
__attribute__((__unused__))
static void _dump_dirents(const inode_t* inode)
{
    if (!S_ISDIR(inode->mode))
        return;

    printf("=== _dump_dirents()\n");

    struct dirent* p = (struct dirent*)inode->buf.data;
    struct dirent* end = (struct dirent*)(inode->buf.data + inode->buf.size);

    printf("inode=%p\n", inode);
    printf("nentries=%zu\n", (end - p));

    while (p != end)
    {
        printf("name{%s}\n", p->d_name);
        p++;
    }

    printf("\n");
}
#endif

static int _inode_new(
    ramfs_t* ramfs,
    inode_t* parent,
    const char* name,
    uint32_t mode,
    inode_t** inode_out)
{
    int ret = 0;
    inode_t* inode = NULL;

    if (inode_out)
        *inode_out = NULL;

    if (!name)
        ERAISE(-EINVAL);

    if (!(inode = calloc(1, sizeof(inode_t))))
        ERAISE(-ENOMEM);

    inode->magic = INODE_MAGIC;
    inode->mode = mode;
    inode->nlink = 1;

    inode->gid = myst_syscall_getegid();
    inode->uid = myst_syscall_geteuid();

    if (_is_shmfs(ramfs) && S_ISREG(mode))
        inode->buf.flags = MYST_BUF_PAGE_ALIGNED;

    /* The root directory is its own parent */
    if (!parent)
        parent = inode;

    /* If new inode is a directory, add the "." and ".." elements */
    if (S_ISDIR(mode))
    {
        /* Add the "." entry */
        ECHECK(_inode_add_dirent(inode, inode, DT_DIR, "."));
        inode->nlink++; /* self link */

        /* Add the ".." entry */
        ECHECK(_inode_add_dirent(inode, parent, DT_DIR, ".."));
    }

    /* Add this inode to the parent's directory table (if not root) */
    if (parent != inode)
    {
        uint8_t type;

        if (S_ISDIR(mode))
            type = DT_DIR;
        else if (S_ISREG(mode) || S_ISCHR(mode))
            type = DT_REG;
        else if (S_ISLNK(mode))
            type = DT_LNK;
        else
        {
            ERAISE(-EINVAL);
        }

        /* add new inode to parent directory */
        {
            ECHECK(_inode_add_dirent(parent, inode, type, name));

            if (S_ISDIR(inode->mode))
                parent->nlink++;
        }
    }

    _update_timestamps(inode, ACCESS | CHANGE | MODIFY);

    if (inode_out)
        *inode_out = inode;

    ramfs->ninodes++;
    inode = NULL;

done:

    if (inode)
        _inode_free(ramfs, inode);

    return ret;
}

static inode_t* _inode_find_child(const inode_t* inode, const char* name)
{
    struct dirent* ents = (struct dirent*)inode->buf.data;
    size_t nents = inode->buf.size / sizeof(struct dirent);

    for (size_t i = 0; i < nents; i++)
    {
        if (strcmp(ents[i].d_name, name) == 0)
            return (inode_t*)ents[i].d_ino;
    }

    /* Not found */
    return NULL;
}

/* Perform a depth-first release of all inodes */
static void _inode_release_all(
    ramfs_t* ramfs,
    inode_t* parent,
    inode_t* inode,
    uint8_t d_type)
{
    struct dirent* ents = (struct dirent*)inode->buf.data;
    size_t nents = inode->buf.size / sizeof(struct dirent);

    /* Free the children first */
    if (d_type == DT_DIR)
    {
        for (size_t i = 0; i < nents; i++)
        {
            const struct dirent* ent = &ents[i];
            inode_t* child;

            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            {
                continue;
            }

            child = (inode_t*)ent->d_ino;
            assert(child);
            assert(_inode_valid(child));

            if (child != inode)
                _inode_release_all(ramfs, inode, child, ent->d_type);
        }

        /* remove self link */
        inode->nlink--;

        /* remove link from parent */
        inode->nlink--;

        /* reduce link in parent */
        if (parent)
            parent->nlink--;
    }
    else
    {
        inode->nlink--;
    }

    if (inode->nlink == 0)
        _inode_free(ramfs, inode);
}

static int _inode_remove_dirent(inode_t* inode, const char* name)
{
    int ret = 0;
    struct dirent* ents = (struct dirent*)inode->buf.data;
    size_t nents = inode->buf.size / sizeof(struct dirent);
    size_t index = (size_t)-1;

    if (!S_ISDIR(inode->mode))
        ERAISE(-ENOTDIR);

    for (size_t i = 0; i < nents; i++)
    {
        if (strcmp(ents[i].d_name, name) == 0)
        {
            const size_t pos = i * sizeof(struct dirent);
            const size_t size = sizeof(struct dirent);

            /* clear the entry */
            memset(&ents[i], 0, sizeof(struct dirent));

            if (myst_buf_remove(&inode->buf, pos, size) != 0)
                ERAISE(-ENOMEM);

            index = i;
            break;
        }
    }

    if (index == (size_t)-1)
        ERAISE(-ENOENT);

    /* Adjust d_off for entries following the deleted entry */
    for (size_t i = index + 1; i < nents - 1; i++)
    {
        ents[i].d_off -= (off_t)sizeof(struct dirent);
    }

    /* update the time fields */
    _update_timestamps(inode, CHANGE | MODIFY);

done:
    return ret;
}

static const char* _inode_target(inode_t* inode)
{
    if (inode->v_cb.open_cb)
        inode->v_cb.open_cb(NULL, &inode->buf, NULL);
    return (const char*)inode->buf.data;
}

/*
**==============================================================================
**
** myst_file_t
**
**==============================================================================
*/

#define FILE_MAGIC 0xdfe1d5c160064f8e

struct myst_file_shared
{
    uint64_t magic;
    inode_t* inode;
    size_t offset;      /* the current file offset (files) */
    uint32_t access;    /* (O_RDONLY | O_RDWR | O_WRONLY) */
    uint32_t operating; /* (O_APPEND | O_DIRECT | O_NOATIME | O_NONBLOCK) */
    char realpath[PATH_MAX];
    myst_buf_t vbuf;           /* virtual file buffer */
    myst_spinlock_t vbuf_lock; /* lock for the virtual file buffer */
    _Atomic(size_t) use_count;
};

struct myst_file
{
    struct myst_file_shared* shared;
    int fdflags; /* file descriptor flags: FD_CLOEXEC */
};

static bool _file_valid(const myst_file_t* file)
{
    return file && file->shared && file->shared->magic == FILE_MAGIC;
}

static void* _file_data(const myst_file_t* file)
{
    return (file->shared->inode->v_cb.open_cb) ? file->shared->vbuf.data
                                               : file->shared->inode->buf.data;
}

static size_t _file_size(const myst_file_t* file)
{
    return (file->shared->inode->v_cb.open_cb) ? file->shared->vbuf.size
                                               : file->shared->inode->buf.size;
}

static void* _file_current(myst_file_t* file)
{
    return (uint8_t*)_file_data(file) + file->shared->offset;
}

static void* _file_at(myst_file_t* file, size_t offset)
{
    return (uint8_t*)_file_data(file) + offset;
}

/*
**==============================================================================
**
** local definitions:
**
**==============================================================================
*/

#define MODE_R (S_IRUSR | S_IRGRP | S_IROTH)
#define MODE_W (S_IWUSR | S_IWGRP | S_IWOTH)
#define MODE_X (S_IXUSR | S_IXGRP | S_IXOTH)
#define MODE_RWX (MODE_R | MODE_W | MODE_X)

/* Assume that d_ino is 8 bytes (big enough to hold a pointer) */
_Static_assert(sizeof(((struct dirent*)0)->d_ino) == 8, "d_ino");

/* Assume struct dirent is eight-byte aligned */
_Static_assert(sizeof(struct dirent) % 8 == 0, "dirent");

static int _path_to_inode_recursive(
    ramfs_t* ramfs,
    const char* path,
    inode_t* parent,
    bool follow,
    inode_t** parent_out,
    inode_t** inode_out,
    char realpath[PATH_MAX],
    char target_out[PATH_MAX])
{
    int ret = 0;
    char** toks = NULL;
    size_t ntoks = 0;
    inode_t* inode = NULL;

    if (inode_out)
        *inode_out = NULL;

    if (parent_out)
        *parent_out = NULL;

    if (!path || !inode_out)
        ERAISE(-EINVAL);

    /* If root directory */
    if (strcmp(path, "/") == 0)
    {
        inode = ramfs->root;

        if (parent_out)
            *parent_out = parent;

        if (realpath)
            myst_strlcpy(realpath, "/", PATH_MAX);

        *inode_out = inode;

        ret = 0;
        goto done;
    }

    /* Split the path into tokens */
    ECHECK(myst_strsplit(path, "/", &toks, &ntoks));

    /* search for the inode */
    {
        for (size_t i = 0; i < ntoks; i++)
        {
            if (!S_ISDIR(parent->mode))
                ERAISE_QUIET(-ENOTDIR);

            inode_t* p;
            if (!(p = _inode_find_child(parent, toks[i])))
                ERAISE_QUIET(-ENOENT);

            if (!S_ISLNK(p->mode))
            {
                if (realpath)
                {
                    if (myst_strlcat(realpath, "/", PATH_MAX) >= PATH_MAX)
                        ERAISE_QUIET(-ENAMETOOLONG);

                    if (myst_strlcat(realpath, toks[i], PATH_MAX) >= PATH_MAX)
                        ERAISE_QUIET(-ENAMETOOLONG);
                }
            }

            if (S_ISLNK(p->mode) && (follow || i + 1 != ntoks))
            {
                const char* target = _inode_target(p);

                if (*target == '/')
                {
                    if (target_out)
                    {
                        myst_strlcpy(target_out, target, PATH_MAX);
                        // Copy over rest of unresolved tokens
                        if (i + 1 != ntoks)
                        {
                            for (size_t j = i + 1; j < ntoks; j++)
                            {
                                if (myst_strlcat(target_out, "/", PATH_MAX) >=
                                    PATH_MAX)
                                    ERAISE_QUIET(-ENAMETOOLONG);

                                if (myst_strlcat(
                                        target_out, toks[j], PATH_MAX) >=
                                    PATH_MAX)
                                    ERAISE_QUIET(-ENAMETOOLONG);
                            }
                        }
                        goto done;
                    }
                    else
                    {
                        if (realpath)
                            *realpath = '\0';

                        parent = ramfs->root;
                    }
                }

                // Ignore self-loops.
                if (strcmp(path, target) != 0)
                {
                    // Recursively resolve links.
                    ECHECK(_path_to_inode_recursive(
                        ramfs,
                        target,
                        parent,
                        true,
                        &parent,
                        &p,
                        realpath,
                        target_out));
                }

                assert(target != NULL);
            }

            /* If final token */
            if (i + 1 == ntoks)
            {
                inode = p;
                break;
            }

            parent = p;
        }

        if (!inode)
            ERAISE_QUIET(-ENOENT);
    }

    *inode_out = inode;

    if (parent_out)
        *parent_out = parent;

done:

    if (toks)
        free(toks);

    return ret;
}

static int _path_to_inode_realpath(
    ramfs_t* ramfs,
    const char* path,
    bool follow,
    inode_t** parent_out,
    inode_t** inode_out,
    char realpath_out[PATH_MAX],
    char target[PATH_MAX])
{
    int ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    *locals->realpath = '\0';

    ECHECK(_path_to_inode_recursive(
        ramfs,
        path,
        ramfs->root,
        follow,
        parent_out,
        inode_out,
        realpath_out ? locals->realpath : NULL,
        target));

    if (realpath_out)
        ECHECK(myst_normalize(locals->realpath, realpath_out, PATH_MAX));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _path_to_inode(
    ramfs_t* ramfs,
    const char* path,
    bool follow,
    inode_t** parent_out,
    inode_t** inode_out,
    char suffix[PATH_MAX],
    myst_fs_t** fs_out)
{
    int ret = 0;
    struct locals
    {
        char target[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (suffix)
    {
        *suffix = '\0';
        *fs_out = NULL;
        *locals->target = '\0';
    }

    ECHECK(_path_to_inode_realpath(
        ramfs, path, follow, parent_out, inode_out, NULL, locals->target));

    if (suffix && *locals->target != '\0' && ramfs->resolve)
    {
        ECHECK((*ramfs->resolve)(locals->target, suffix, fs_out));
    }

done:

    if (locals)
        free(locals);

    return ret;
}

/*
**==============================================================================
**
** interface:
**
**==============================================================================
*/

static int _fs_release(myst_fs_t* fs)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    _inode_release_all(ramfs, NULL, ramfs->root, DT_DIR);

    if (ramfs->ninodes != 0)
        myst_panic("_ninodes != 0");

    assert(ramfs->ninodes == 0);

    free(ramfs);

done:
    return ret;
}

static int _fs_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !target)
        ERAISE(-EINVAL);

    if (myst_strlcpy(ramfs->target, target, PATH_MAX) >= PATH_MAX)
        ERAISE(-ENAMETOOLONG);

    if (myst_strlcpy(ramfs->source, source, PATH_MAX) >= PATH_MAX)
        ERAISE(-ENAMETOOLONG);

done:
    return ret;
}

static int _fs_creat(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file)
{
    int ret = 0;
    const int flags = O_CREAT | O_WRONLY | O_TRUNC;

    if (!fs)
        ERAISE(-EINVAL);

    ERAISE((*fs->fs_open)(fs, pathname, flags, mode, fs_out, file));

done:
    return ret;
}

static int _fs_open(
    myst_fs_t* fs,
    const char* pathname,
    int flags,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode = NULL;
    myst_file_t* file = NULL;
    myst_file_shared_t* file_shared = NULL;
    int ret = 0;
    int errnum;
    bool follow = true;
    bool is_i_new = false;
    myst_fs_t* tfs = NULL;
    struct locals
    {
        char suffix[PATH_MAX];
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (file_out)
        *file_out = NULL;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!pathname)
        ERAISE(-EINVAL);

    if (!file_out)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Create the file object */
    if (!(file = calloc(1, sizeof(myst_file_t))))
        ERAISE(-ENOMEM);

    if (!(file_shared = calloc(1, sizeof(myst_file_shared_t))))
        ERAISE(-ENOMEM);

    file->shared = file_shared;

    /* handle O_NOFOLLOW flag (applies to final component of path) */
    if ((flags & O_NOFOLLOW))
        follow = false;

    errnum = _path_to_inode(
        ramfs, pathname, follow, NULL, &inode, locals->suffix, &tfs);

    if (tfs)
    {
        /* delegate open operation to target filesystem */
        ECHECK(
            (ret = tfs->fs_open(
                 tfs, locals->suffix, flags, mode, fs_out, file_out)));
        goto done;
    }
    else if (fs_out)
    {
        /* i.e, path resolving has terminated,
        file resides in the current fs. */
        if (ramfs->lockfs)
            *fs_out = ramfs->lockfs;
        else
            *fs_out = (myst_fs_t*)ramfs;
    }

    /* If the file already exists */
    if (errnum == 0)
    {
        if ((flags & O_CREAT) && (flags & O_EXCL))
            ERAISE(-EEXIST);

        /* bail out as this fs doesn't support O_TMPFILE (yet) */
        if ((flags & O_TMPFILE) && ((flags & O_RDWR) || (flags & O_WRONLY)) &&
            S_ISDIR(inode->mode))
        {
            ERAISE(-EISDIR);
        }

        if (S_ISLNK(inode->mode) && (flags & O_NOFOLLOW) && !(flags & O_PATH))
            ERAISE(-ELOOP);

        /* Check file access permissions */
        {
            const int access = (flags & O_PATH)
                                   ? O_PATH
                                   : flags & (O_RDONLY | O_RDWR | O_WRONLY);

            if (access == O_RDONLY && !(inode->mode & S_IRUSR))
                ERAISE(-EPERM);

            if (access == O_WRONLY && !(inode->mode & S_IWUSR))
                ERAISE(-EPERM);

            if (access == O_RDWR && !(inode->mode & S_IRUSR))
                ERAISE(-EPERM);

            if (access == O_RDWR && !(inode->mode & S_IWUSR))
                ERAISE(-EPERM);
        }

        if ((flags & O_DIRECTORY) && !S_ISDIR(inode->mode))
            ERAISE(-ENOTDIR);

        if ((flags & O_TRUNC))
            myst_buf_clear(&inode->buf);

        /* Get the realpath of this file */
        ECHECK(_path_to_inode_realpath(
            ramfs, pathname, true, NULL, &inode, file->shared->realpath, NULL));

        if (inode->v_cb.open_cb)
            ECHECK((*inode->v_cb.open_cb)(
                file, &file->shared->vbuf, file->shared->realpath));
    }
    else if (errnum == -ENOENT)
    {
        inode_t* parent;

        is_i_new = true;

        if (!(flags & O_CREAT))
            ERAISE(-ENOENT);

        /* Split the path into parent directory and file name */
        ECHECK(_split_path(pathname, locals->dirname, locals->basename));

        /* Get the inode of the parent directory, symbolic link in the directory
         * part of the path should always be followed */
        ECHECK(_path_to_inode(
            ramfs, locals->dirname, true, NULL, &parent, NULL, NULL));

        /* Create the new file inode */
        /* ATTN: Current ramfs only support S_IFREG or S_ISCHR (virtual /dev) */
        if (!S_ISCHR(mode))
        {
            /* in case upper layer does not set file type in mode */
            mode = mode | S_IFREG;
        }
        ECHECK(_inode_new(ramfs, parent, locals->basename, mode, &inode));

        /* Get the realpath of this file */
        ECHECK(_path_to_inode_realpath(
            ramfs,
            pathname,
            follow,
            NULL,
            &inode,
            file->shared->realpath,
            NULL));
    }
    else
    {
        ERAISE(-errnum);
    }

    /* Initialize the file */
    file->shared->magic = FILE_MAGIC;
    file->shared->inode = inode;
    file->shared->access =
        (flags & O_PATH) ? O_PATH : (flags & (O_RDONLY | O_RDWR | O_WRONLY));
    file->shared->operating = (flags & (O_APPEND | O_NONBLOCK));
    file->shared->use_count = 1;
    inode->nopens++;

    assert(_file_valid(file));

    *file_out = file;
    file = NULL;
    file_shared = NULL;
    inode = NULL;

done:

    if (locals)
        free(locals);

    if (inode && is_i_new)
        _inode_free(ramfs, inode);

    if (file)
        free(file);

    if (file_shared)
        free(file_shared);

    return ret;
}

static off_t _fs_lseek(
    myst_fs_t* fs,
    myst_file_t* file,
    off_t offset,
    int whence)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    off_t ret = 0;
    off_t new_offset = 0;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* NOP for read and write callbacks based virtual files */
    if (_is_virtual_inode(file->shared->inode))
        goto done;

    switch (whence)
    {
        case SEEK_SET:
        {
            new_offset = offset;
            break;
        }
        case SEEK_CUR:
        {
            new_offset = (off_t)file->shared->offset + offset;
            break;
        }
        case SEEK_END:
        {
            new_offset = (off_t)_file_size(file) + offset;
            break;
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

    /* ATTN: support seeking beyond the end of file, deficiency compared with
     * EXT2FS support */

    /* Check whether new offset if out of range */
    if (new_offset < 0 || new_offset > (off_t)_file_size(file))
        ERAISE(-EINVAL);

    file->shared->offset = (size_t)new_offset;

    _update_timestamps(file->shared->inode, ACCESS);

    ret = new_offset;

done:
    return ret;
}

static ssize_t _fs_read(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    ssize_t ret = 0;
    size_t n;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    /* fail if file has been opened for write only */
    if (file->shared->access == O_WRONLY || file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* reading zero bytes is okay */
    if (!count)
        goto done;

    /* If read-time virtual file, populate buf via callback */
    if (file->shared->inode->v_cb.read_cb)
    {
        ret = file->shared->inode->v_cb.read_cb(file, buf, count);
        goto done;
    }

    /* If offset is beyond end of file, return 0 */
    if (file->shared->offset >= _file_size(file))
        goto done;

    /* Read count bytes from the file or directory */
    {
        size_t remaining = _file_size(file) - file->shared->offset;

        if (remaining == 0)
        {
            /* end of file */
            goto done;
        }

        n = (count < remaining) ? count : remaining;
        memcpy(buf, _file_current(file), n);
        file->shared->offset += n;
    }

    _update_timestamps(file->shared->inode, ACCESS);

    ret = (ssize_t)n;

done:
    return ret;
}

static bool is_posix_shmfs_active_file(ramfs_t* ramfs, inode_t* inode)
{
    assert(ramfs && _ramfs_valid(ramfs));
    assert(inode && _inode_valid(inode));
    if (_is_shmfs(ramfs) && S_ISREG(inode->mode) &&
        inode->buf.flags & MYST_BUF_ACTIVE_MAPPING)
        return true;
    return false;
}

static ssize_t _fs_write(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    ssize_t ret = 0;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    /* writing zero bytes is okay */
    if (!count)
        goto done;

    /* fail if file has been opened for read only */
    if (file->shared->access == O_RDONLY || file->shared->access == O_PATH)
        ERAISE(-EBADF);

    /* If write-time virtual file, write to buf via callback */
    if (file->shared->inode->v_cb.write_cb)
    {
        ret = file->shared->inode->v_cb.write_cb(file, buf, count);
        goto done;
    }

    /* append always writes to the end of the file */
    if ((file->shared->operating & O_APPEND))
        file->shared->offset = _file_size(file);

    /* Verify that the offset is in bounds */
    if (file->shared->offset > _file_size(file))
        ERAISE(-EINVAL);

    /* Write count bytes to the file or directory */
    {
        size_t new_offset = file->shared->offset + count;

        if (new_offset > _file_size(file))
        {
            if (is_posix_shmfs_active_file(ramfs, file->shared->inode))
            {
                MYST_WLOG("Unsupported Operation: Attempt was made to write to "
                          "a posix shared memory file with active mappings.");
                ERAISE(-EINVAL);
            }

            if (myst_buf_resize(&file->shared->inode->buf, new_offset) != 0)
                ERAISE(-ENOMEM);
        }

        memcpy(_file_current(file), buf, count);
        file->shared->offset = new_offset;
    }

    _update_timestamps(file->shared->inode, MODIFY | CHANGE);

    ret = (ssize_t)count;

done:
    return ret;
}

static ssize_t _fs_pread(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count,
    off_t offset)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    ssize_t ret = 0;
    size_t n;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (offset < 0)
        ERAISE(-EINVAL);

    /* reading zero bytes is okay */
    if (!count)
        goto done;

    /* If read-time virtual file, populate buf via callback */
    if (file->shared->inode->v_cb.read_cb)
    {
        ret = file->shared->inode->v_cb.read_cb(file, buf, count);
        goto done;
    }

    /* Verify that the offset is in bounds */
    if ((size_t)offset > _file_size(file))
        ERAISE(-EINVAL);

    /* Read count bytes from the file or directory */
    {
        size_t remaining = _file_size(file) - (size_t)offset;

        if (remaining == 0)
        {
            /* end of file */
            goto done;
        }

        n = (count < remaining) ? count : remaining;
        memcpy(buf, _file_at(file, (size_t)offset), n);
    }

    _update_timestamps(file->shared->inode, ACCESS);

    ret = (ssize_t)n;

done:
    return ret;
}

static ssize_t _fs_pwrite(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count,
    off_t offset)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    ssize_t ret = 0;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (offset < 0)
        ERAISE(-EINVAL);

    /* Writing zero bytes is okay */
    if (!count)
        goto done;

    /* If write-time virtual file, write to buf via callback */
    if (file->shared->inode->v_cb.write_cb)
    {
        ret = file->shared->inode->v_cb.write_cb(file, buf, count);
        goto done;
    }

    /* Write count bytes to the file or directory */
    {
        // When opened for append, Linux pwrite() appends data to the end of
        // file regadless of the offset.
        if ((file->shared->operating & O_APPEND))
            offset = _file_size(file);

        size_t new_offset = (size_t)offset + count;

        if (new_offset > _file_size(file))
        {
            if (is_posix_shmfs_active_file(ramfs, file->shared->inode))
            {
                MYST_WLOG("Unsupported Operation: Attempt was made to write to "
                          "a posix shared memory file with active mappings.");
                ERAISE(-EINVAL);
            }

            if (myst_buf_resize(&file->shared->inode->buf, new_offset) != 0)
                ERAISE(-ENOMEM);
        }

        memcpy(_file_at(file, (size_t)offset), buf, count);
    }

    _update_timestamps(file->shared->inode, CHANGE | MODIFY);

    ret = (ssize_t)count;

done:
    return ret;
}

static ssize_t _fs_readv(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    ssize_t total = 0;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    for (int i = 0; i < iovcnt; i++)
    {
        ssize_t n;
        void* buf = iov[i].iov_base;
        size_t count = iov[i].iov_len;

        ECHECK((n = (*fs->fs_read)(fs, file, buf, count)));

        total += n;

        if ((size_t)n < count)
            break;
    }

    ret = total;

done:
    return ret;
}

static ssize_t _fs_writev(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    ssize_t total = 0;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    for (int i = 0; i < iovcnt; i++)
    {
        ssize_t n;
        const void* buf = iov[i].iov_base;
        size_t count = iov[i].iov_len;

        ECHECK((n = (*fs->fs_write)(fs, file, buf, count)));

        total += n;

        if ((size_t)n < count)
            break;
    }

    ret = total;

done:
    return ret;
}

static int _fs_close(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    assert(file->shared->inode);
    assert(_inode_valid((inode = file->shared->inode)));
    assert(inode->nopens > 0);

    if (--file->shared->use_count == 0)
    {
        /* If a virtual file has a close-callback, call it */
        if (inode->v_cb.close_cb)
            inode->v_cb.close_cb(file);

        /* For open-time virtual files, release the virtual file
        data on close */
        if (inode->v_cb.open_cb)
            myst_buf_release(&file->shared->vbuf);

        inode->nopens--;

        bool active_mmaps =
            (_is_shmfs(ramfs) && myst_buf_has_active_mmap(&inode->buf));
        /* handle case where file was deleted while open */
        if (!active_mmaps && inode->nlink == 0 && inode->nopens == 0)
        {
            _inode_free(ramfs, inode);
        }
        else
        {
            _update_timestamps(inode, ACCESS);
        }

        memset(file->shared, 0xdd, sizeof(myst_file_t));
        free(file->shared);
    }

    /* free file descriptor level object */
    memset(file, 0xdd, sizeof(myst_file_t));
    free(file);
done:
    return ret;
}

static int _fs_access(myst_fs_t* fs, const char* pathname, int mode)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (mode != F_OK && !(mode & (R_OK | W_OK | X_OK)))
        ERAISE(-EINVAL);

    /* Get the inode for pathname */
    ECHECK(_path_to_inode(
        ramfs, pathname, true, NULL, &inode, locals->suffix, &tfs));

    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_access(tfs, locals->suffix, mode)));
        goto done;
    }

    if (mode == F_OK)
        goto done;

    if ((mode & R_OK) && !(inode->mode & S_IRUSR))
        ERAISE(-EACCES);

    if ((mode & W_OK) && !(inode->mode & S_IWUSR))
        ERAISE(-EACCES);

    if ((mode & X_OK) && !(inode->mode & S_IXUSR))
        ERAISE(-EACCES);

    _update_timestamps(inode, ACCESS);

done:

    if (locals)
        free(locals);

    return ret;
}

static int _stat(ramfs_t* ramfs, inode_t* inode, struct stat* statbuf)
{
    int ret = 0;
    struct stat buf;
    off_t rounded;
    size_t size;

    if (!_inode_valid(inode) || !statbuf)
        ERAISE(-EINVAL);

    // Linux doesn't report size for /proc and /dev virtual files
    if (_is_virtual_inode(inode))
    {
        size = 0;
    }
    else
    {
        size = inode->buf.size;
        ECHECK(myst_round_up_signed(size, BLKSIZE, &rounded));
    }

    memset(&buf, 0, sizeof(buf));
    buf.st_dev = ramfs->device_num;
    buf.st_ino = (ino_t)inode;
    buf.st_mode = inode->mode;
    buf.st_nlink = inode->nlink;
    buf.st_uid = inode->uid;
    buf.st_gid = inode->gid;
    buf.st_rdev = 0;
    buf.st_size = (off_t)size;
    buf.st_blksize = BLKSIZE;
    buf.st_blocks = rounded / BLKSIZE;
    buf.st_ctim = inode->ctime;
    buf.st_mtim = inode->mtime;
    buf.st_atim = inode->atime;

    *statbuf = buf;

done:
    return ret;
}

static int _fs_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_inode(
        ramfs, pathname, true, NULL, &inode, locals->suffix, &tfs));
    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_stat(tfs, locals->suffix, statbuf)));
        goto done;
    }
    ERAISE(_stat(ramfs, inode, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_inode(
        ramfs, pathname, false, NULL, &inode, locals->suffix, &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_lstat(tfs, locals->suffix, statbuf));
        goto done;
    }
    ERAISE(_stat(ramfs, inode, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !statbuf)
        ERAISE(-EINVAL);

    assert(_inode_valid(file->shared->inode));
    ERAISE(_stat(ramfs, file->shared->inode, statbuf));

done:
    return ret;
}

static int _fs_link(
    myst_fs_t* fs,
    const char* oldpath,
    const char* newpath,
    int flags)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* old_inode;
    inode_t* new_parent;
    struct locals
    {
        char new_dirname[PATH_MAX];
        char new_basename[PATH_MAX];
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs;

    if (!_ramfs_valid(ramfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    bool oldpath_follow = false;

    if (flags & AT_SYMLINK_FOLLOW)
        oldpath_follow = true;

    /* Find the inode for oldpath */
    ECHECK(_path_to_inode(
        ramfs,
        oldpath,
        oldpath_follow,
        NULL,
        &old_inode,
        locals->suffix,
        &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((ret = tfs->fs_link(tfs, locals->suffix, newpath, flags)));
        goto done;
    }

    /* oldpath must not be a directory */
    if (S_ISDIR(old_inode->mode))
        ERAISE(-EPERM);

    /* Find the parent inode of newpath */
    ECHECK(_split_path(newpath, locals->new_dirname, locals->new_basename));
    ECHECK(_path_to_inode(
        ramfs, locals->new_dirname, false, NULL, &new_parent, NULL, NULL));

    /* Fail if newpath already exists */
    if (_inode_find_child(new_parent, locals->new_basename) != NULL)
        ERAISE(-EEXIST);

    /* Add the directory entry for the newpath */
    _inode_add_dirent(new_parent, old_inode, DT_REG, locals->new_basename);

    /* Increment the file's link count */
    old_inode->nlink++;

    _update_timestamps(old_inode, CHANGE);

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_unlink(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    struct locals
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    inode_t* parent;
    inode_t* inode;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Get the inode for pathname */
    ECHECK(_path_to_inode(
        ramfs, pathname, false, NULL, &inode, locals->suffix, &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((*tfs->fs_unlink)(tfs, locals->suffix));
        goto done;
    }

    /* fail if pathname is a non-empty directory */
    if (S_ISDIR(inode->mode) && !_inode_is_empty_dir(inode))
        ERAISE(-EPERM);

    /* Get the parent inode */
    ECHECK(_split_path(pathname, locals->dirname, locals->basename));
    ECHECK(_path_to_inode(
        ramfs, locals->dirname, true, NULL, &parent, NULL, NULL));

    /* Find and remove the parent's directory entry */
    {
        ECHECK(_inode_remove_dirent(parent, locals->basename));

        if (S_ISDIR(inode->mode))
            parent->nlink--;
    }

    /* remove parent directory link to this inode */
    inode->nlink--;

    if (S_ISDIR(inode->mode))
    {
        /* remove self link if there are no other links */
        if (inode->nlink == 1)
            inode->nlink--;
    }

    // Delete the inode immediately if it's a symbolic link
    // or nobody owned. The deletion is delayed to _fs_close
    // if file is still linked or opened by someone.
    // For shm files, cleanup also needs to wait for existing mappings related
    // to the file to be unmapped.
    if (S_ISLNK(inode->mode) || (inode->nlink == 0 && inode->nopens == 0))
    {
        if (!_is_shmfs(ramfs) || !myst_buf_has_active_mmap(&inode->buf))
            _inode_free(ramfs, inode);
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    struct locals
    {
        char old_dirname[PATH_MAX];
        char old_basename[PATH_MAX];
        char new_dirname[PATH_MAX];
        char new_basename[PATH_MAX];
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    inode_t* old_parent = NULL;
    inode_t* old_inode = NULL;
    inode_t* new_parent = NULL;
    inode_t* new_inode = NULL;
    myst_fs_t* tfs = NULL;

    /* ATTN: check attempt to make subdirectory a directory of itself */
    /* ATTN: check where newpath contains a prefix of oldpath */

    if (!_ramfs_valid(ramfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Split oldpath */
    ECHECK(_split_path(oldpath, locals->old_dirname, locals->old_basename));

    /* Find the oldpath inode */
    ECHECK(_path_to_inode(
        ramfs, oldpath, false, &old_parent, &old_inode, locals->suffix, &tfs));
    if (tfs)
    {
        /* append old_basename and delegate operation to target filesystem */
        if (myst_strlcat(locals->suffix, "/", PATH_MAX) >= PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        if (myst_strlcat(locals->suffix, locals->old_basename, PATH_MAX) >=
            PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);
        ECHECK(tfs->fs_rename(tfs, locals->suffix, newpath));
        goto done;
    }

    /* Split newpath */
    ECHECK(_split_path(newpath, locals->new_dirname, locals->new_basename));

    /* Get the parent of newpath */
    ECHECK(_path_to_inode(
        ramfs, locals->new_dirname, true, NULL, &new_parent, NULL, NULL));

    /* Get the newpath inode (if any) */
    new_inode = _inode_find_child(new_parent, locals->new_basename);

    /* Succeed if oldpath and newpath refer to the same inode */
    if (new_inode == old_inode)
        goto done;

    /* If oldpath is a directory and newpath exists */
    if (S_ISDIR(old_inode->mode) && new_inode)
    {
        if (_inode_is_empty_dir(new_inode))
            ERAISE(-ENOTEMPTY);
    }

    /* Fail if newpath is a directory but oldpath is not */
    if (new_inode && S_ISDIR(new_inode->mode) && !S_ISDIR(old_inode->mode))
        ERAISE(-ENOTDIR);

    /* Remove the oldpath directory entry */
    {
        ECHECK(_inode_remove_dirent(old_parent, locals->old_basename));

        if (S_ISDIR(old_inode->mode))
            old_parent->nlink--;
    }

    /* Remove the newpath directory entry if any */
    if (new_inode)
    {
        ECHECK(_inode_remove_dirent(new_parent, locals->new_basename));

        if (S_ISDIR(new_inode->mode))
            new_parent->nlink--;

        new_inode->nlink--;
    }

    /* Add the newpath directory entry */
    {
        const uint8_t type = S_ISDIR(old_inode->mode) ? DT_DIR : DT_REG;

        _inode_add_dirent(new_parent, old_inode, type, locals->new_basename);

        if (S_ISDIR(old_inode->mode))
            new_parent->nlink++;
    }

    /* Dereference the new inode (if any) */
    if (new_inode && new_inode->nlink == 0)
        _inode_free(ramfs, new_inode);

done:

    if (locals)
        free(locals);

    return ret;
}

static int _truncate(ramfs_t* ramfs, inode_t* inode, size_t length)
{
    int ret = 0;

    /* truncate does not apply to virtual files */
    if (_is_virtual_inode(inode))
        ERAISE(-EINVAL);

    if (is_posix_shmfs_active_file(ramfs, inode))
    {
        MYST_WLOG("Unsupported Operation: Attempt was made to truncate "
                  "a posix shared memory file with active mappings.");
        ERAISE(-EINVAL);
    }

    if (myst_buf_resize(&inode->buf, length) != 0)
        ERAISE(-ENOMEM);

    _update_timestamps(inode, CHANGE | MODIFY);

done:
    return ret;
}

static int _fs_truncate(myst_fs_t* fs, const char* pathname, off_t length)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname || length < 0)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_inode(
        ramfs, pathname, true, NULL, &inode, locals->suffix, &tfs));
    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_truncate(tfs, locals->suffix, length)));
        goto done;
    }

    if (S_ISDIR(inode->mode))
        ERAISE(-EISDIR);

    ECHECK(_truncate(ramfs, inode, (size_t)length));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    uint32_t access;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || length < 0)
        ERAISE(-EINVAL);

    if (S_ISDIR(file->shared->inode->mode))
        ERAISE(-EISDIR);

    access = file->shared->access;

    if (access == O_PATH)
        ERAISE(-EBADF);

    if (!((access & O_RDWR) || (access & O_WRONLY)))
        ERAISE(-EINVAL);

    ECHECK(_truncate(ramfs, file->shared->inode, (size_t)length));

done:
    return ret;
}

static int _fs_mkdir(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    struct locals
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    inode_t* parent;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_split_path(pathname, locals->dirname, locals->basename));
    ECHECK(_path_to_inode(
        ramfs, locals->dirname, true, NULL, &parent, locals->suffix, &tfs));
    if (tfs)
    {
        /* append basename and delegate operation to target filesystem */
        if (myst_strlcat(locals->suffix, "/", PATH_MAX) >= PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        if (myst_strlcat(locals->suffix, locals->basename, PATH_MAX) >=
            PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        ECHECK((*tfs->fs_mkdir)(tfs, locals->suffix, mode));
        goto done;
    }

    /* The parent must be a directory */
    if (!S_ISDIR(parent->mode))
        ERAISE(-ENOTDIR);

    /* Check whether the pathname already exists */
    if (_inode_find_child(parent, locals->basename) != NULL)
        ERAISE(-EEXIST);

    /* create the directory */
    ERAISE(_inode_new(ramfs, parent, locals->basename, (S_IFDIR | mode), NULL));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_rmdir(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    struct locals
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    inode_t* parent;
    inode_t* child;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Get the child inode */
    ECHECK(_path_to_inode(
        ramfs, pathname, true, NULL, &child, locals->suffix, &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK(tfs->fs_rmdir(tfs, locals->suffix));
        goto done;
    }

    /* The child must be a directory */
    if (!S_ISDIR(child->mode))
        ERAISE(-ENOTDIR);

    /* Make sure the directory has no children */
    if (child->buf.size > (2 * sizeof(struct dirent)))
        ERAISE(-ENOTEMPTY);

    /* Get the parent inode */
    ECHECK(_split_path(pathname, locals->dirname, locals->basename));
    ECHECK(_path_to_inode(
        ramfs, locals->dirname, true, NULL, &parent, NULL, NULL));

    /* Find and remove the parent directory entry */
    ECHECK(_inode_remove_dirent(parent, locals->basename));
    parent->nlink--;

    /* remove the parent directory link to this inode */
    assert(child->nlink > 0);
    child->nlink--;

    /* remove the self link */
    assert(child->nlink > 0);
    child->nlink--;

    /* If no more links to this inode, then free it */
    if (child->nlink == 0 && child->nopens == 0)
        _inode_free(ramfs, child);

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_getdents64(
    myst_fs_t* fs,
    myst_file_t* file,
    struct dirent* dirp,
    size_t count)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    size_t n = count / sizeof(struct dirent);
    size_t bytes = 0;
    struct locals
    {
        struct dirent ent;
    };
    struct locals* locals = NULL;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !dirp)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (count == 0)
        goto done;

    /* in case an entry was deleted (by unlink) during this iteration */
    if (file->shared->offset >= file->shared->inode->buf.size)
        file->shared->offset = file->shared->inode->buf.size;

    for (size_t i = 0; i < n; i++)
    {
        ssize_t r;

        /* Read next entry and break on end-of-file */
        if ((r = _fs_read(fs, file, &locals->ent, sizeof(locals->ent))) == 0)
            break;

        /* Fail if exactly one entry was not read */
        if (r != sizeof(locals->ent))
            myst_panic("unexpected");

        *dirp = locals->ent;
        bytes += sizeof(struct dirent);
        dirp++;
    }

    ret = (int)bytes;

done:

    if (locals)
        free(locals);

    return ret;
}

static ssize_t _fs_readlink(
    myst_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    ssize_t ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname || !buf || !bufsiz)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Get the inode for pathname */
    ECHECK(_path_to_inode(
        ramfs, pathname, false, NULL, &inode, locals->suffix, &tfs));
    if (tfs)
    {
        /* delegate operation to target filesystem */
        ECHECK((ret = tfs->fs_readlink(tfs, locals->suffix, buf, bufsiz)));
        goto done;
    }

    if (!S_ISLNK(inode->mode))
        ERAISE(-EINVAL);

    if (inode->v_cb.open_cb)
    {
        inode->v_cb.open_cb(NULL, &inode->buf, NULL);
    }
    else
    {
        assert(inode->buf.data);
        assert(inode->buf.size);
    }

    if (!inode->buf.data || !inode->buf.size)
        ERAISE(-EINVAL);

    _update_timestamps(inode, ACCESS);

    ret = (ssize_t)myst_strlcpy(buf, (char*)inode->buf.data, bufsiz);

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode = NULL;
    inode_t* parent = NULL;
    struct locals
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!target || !linkpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Split linkpath into directory and filename */
    ECHECK(_split_path(linkpath, locals->dirname, locals->basename));

    /* Get the inode of the parent directory */
    ECHECK(_path_to_inode(
        ramfs, locals->dirname, true, NULL, &parent, locals->suffix, &tfs));
    if (tfs)
    {
        /* append basename and delegate operation to target filesystem */
        if (myst_strlcat(locals->suffix, "/", PATH_MAX) >= PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);

        if (myst_strlcat(locals->suffix, locals->basename, PATH_MAX) >=
            PATH_MAX)
            ERAISE_QUIET(-ENAMETOOLONG);
        ECHECK((*tfs->fs_symlink)(tfs, target, locals->suffix));
        goto done;
    }

    /* Create the new link inode */
    ECHECK(
        _inode_new(ramfs, parent, locals->basename, (S_IFLNK | 0777), &inode));

    /* Write the target name into the link inode */
    if (myst_buf_append(&inode->buf, target, strlen(target) + 1) != 0)
        ERAISE(-ENOMEM);

    inode = NULL;
done:
    if (inode)
        _inode_free(ramfs, inode);

    if (locals)
        free(locals);

    return ret;
}

static int _fs_realpath(
    myst_fs_t* fs,
    myst_file_t* file,
    char* buf,
    size_t size)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !buf || !size)
        ERAISE(-EINVAL);

    if (strcmp(ramfs->target, "/") == 0)
    {
        if (myst_strlcpy(buf, file->shared->realpath, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        if (myst_strlcpy(buf, ramfs->target, size) >= size)
            ERAISE(-ENAMETOOLONG);

        if (myst_strlcat(buf, file->shared->realpath, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

static void _set_fd_flag(myst_file_t* file, long arg)
{
    assert(_file_valid(file));

    /* Linux currently only defines a single flag, FD_CLOEXEC */
    if (arg & FD_CLOEXEC)
        file->fdflags = FD_CLOEXEC;
    else
        file->fdflags = 0;

    _update_timestamps(file->shared->inode, CHANGE);
}

static int _fs_fcntl(myst_fs_t* fs, myst_file_t* file, int cmd, long arg)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    switch (cmd)
    {
        case F_SETFD:
        {
            _set_fd_flag(file, arg);
            goto done;
        }
        case F_GETFD:
        {
            ret = file->fdflags;
            goto done;
        }
        case F_GETFL:
        {
            ret = (int)(file->shared->access | file->shared->operating);
            goto done;
        }
        case F_SETFL:
        {
            if (arg & O_APPEND)
                file->shared->operating |= O_APPEND;
            if (arg & O_NONBLOCK)
                file->shared->operating |= O_NONBLOCK;
            if (arg & O_DIRECT)
                // ATTN: implement O_DIRECT for files
                file->shared->operating |= O_DIRECT;
            if (arg & O_NOATIME)
                // ATTN: implement O_NOATIME for files
                file->shared->operating |= O_NOATIME;
            goto done;
        }
        case F_SETLK:
        case F_SETLKW:
        {
            /* ATTN: silently ignoring locking for now */
            goto done;
        }
        default:
        {
            ERAISE(-ENOTSUP);
        }
    }

done:
    return ret;
}

static int _fs_ioctl(
    myst_fs_t* fs,
    myst_file_t* file,
    unsigned long request,
    long arg)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    int ret = 0;

    (void)arg;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EBADF);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    switch (request)
    {
        case TIOCGWINSZ:
        {
            if (!devfs_is_pty_pts_device(file))
                ERAISE(-EINVAL);
            break;
        }
        case FIOCLEX:
        {
            _set_fd_flag(file, FD_CLOEXEC);
            break;
        }
        case FIONCLEX:
        {
            _set_fd_flag(file, 0);
            break;
        }
        case FIONBIO:
        {
            int* val = (int*)arg;

            if (!val)
                ERAISE(-EINVAL);

            if (*val)
                file->shared->operating |= O_NONBLOCK;
            else
                file->shared->operating &= ~O_NONBLOCK;

            break;
        }
        case TIOCSPTLCK:
        {
            if (!devfs_is_pty_pts_device(file))
                ERAISE(-ENOTTY);
            // NOP. The PTY slave is always ready to serve.
            break;
        }
        case TIOCGPTN:
        {
            if (!devfs_is_pty_pts_device(file))
                ERAISE(-ENOTTY);
            int* id = (int*)arg;
            ret = devfs_get_pts_id(file, id);
            break;
        }
        case TCGETS:
        case TCSETS:
        case TCSETS + 1:
        case TCSETS + 2:
        {
            if (!devfs_is_pty_pts_device(file))
                ERAISE(-ENOTTY);
            break;
        }
        default:
            ERAISE(-ENOTSUP);
    }

done:

    return ret;
}

static int _fs_dup(
    myst_fs_t* fs,
    const myst_file_t* file,
    myst_file_t** file_out)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    int ret = 0;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !file_out)
        ERAISE(-EINVAL);

    if (!((*file_out) = calloc(1, sizeof(myst_file_t))))
        ERAISE(-ENOMEM);

    (*file_out)->shared = ((myst_file_t*)file)->shared;
    (*file_out)->fdflags = 0;
    (*file_out)->shared->use_count++;

done:

    return ret;
}

static int _fs_target_fd(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _fs_get_events(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    /* Regular files always poll TRUE for reads and writes */
    ret |= POLLIN;
    ret |= POLLOUT;

done:
    return ret;
}

static int _statfs(struct statfs* buf)
{
    int ret = 0;

    if (!buf)
        ERAISE(-EINVAL);

    memset(buf, 0, sizeof(struct statfs));
    buf->f_type = 0x858458f6; // RAMFS_MAGIC from man(2) statfs
    buf->f_bsize = BLKSIZE;

done:
    return ret;
}

static int _fs_statfs(myst_fs_t* fs, const char* pathname, struct statfs* buf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname || !buf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ramfs, pathname, true, NULL, &inode, locals->suffix, &tfs));
    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_statfs(tfs, locals->suffix, buf)));
        goto done;
    }
    ECHECK(_statfs(buf));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_fstatfs(myst_fs_t* fs, myst_file_t* file, struct statfs* buf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !buf)
        ERAISE(-EINVAL);

    ECHECK(_statfs(buf));

done:
    return ret;
}

static int _fs_futimens(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct timespec times[2])
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (times)
    {
        switch (times[0].tv_nsec)
        {
            case UTIME_OMIT:
                break;
            case UTIME_NOW:
                _update_timestamps(file->shared->inode, ACCESS);
                break;
            default:
                file->shared->inode->atime = times[0];
                break;
        }

        switch (times[1].tv_nsec)
        {
            case UTIME_OMIT:
                break;
            case UTIME_NOW:
                _update_timestamps(file->shared->inode, MODIFY);
                break;
            default:
                file->shared->inode->atime = times[1];
                break;
        }
    }
    else
    {
        /* set to current time */
        _update_timestamps(file->shared->inode, ACCESS | MODIFY);
    }

done:
    return ret;
}

static int _chown(inode_t* inode, uid_t owner, gid_t group)
{
    int ret = 0;

    if (!inode)
        ERAISE(-EINVAL);

    if (owner != -1u)
        inode->uid = owner;

    if (group != -1u)
        inode->gid = group;

    /* For executables, clear set-user-ID and set-group-ID bits */
    if (inode->mode & (S_IXUSR | S_IXGRP | S_IXOTH))
    {
        if (inode->mode & S_ISUID)
            inode->mode &= ~S_ISUID;

        /* Only clear set-group-id bit for group executables */
        if ((inode->mode & S_ISGID) && (inode->mode & S_IXGRP))
            inode->mode &= ~S_ISGID;
    }

    _update_timestamps(inode, CHANGE);

done:

    return ret;
}

static int _fs_chown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    struct locals
    {
        inode_t* inode;
        char suffix[PATH_MAX];
    }* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ramfs, pathname, true, NULL, &locals->inode, locals->suffix, &tfs));
    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_chown(tfs, locals->suffix, owner, group)));
        goto done;
    }

    ECHECK(_chown(locals->inode, owner, group));

done:

    if (locals)
        free(locals);

    return ret;
}

int _fs_fchown(myst_fs_t* fs, myst_file_t* file, uid_t owner, gid_t group)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !file)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    assert(_inode_valid(file->shared->inode));
    ECHECK(_chown(file->shared->inode, owner, group));

done:
    return ret;
}

static int _fs_lchown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    struct locals
    {
        inode_t* inode;
        char suffix[PATH_MAX];
    }* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ramfs, pathname, false, NULL, &locals->inode, locals->suffix, &tfs));
    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_lchown(tfs, locals->suffix, owner, group)));
        goto done;
    }

    if (!S_ISLNK(locals->inode->mode))
        ERAISE(-ENOTDIR);

    ECHECK(_chown(locals->inode, owner, group));

done:

    if (locals)
        free(locals);

    return ret;
}

#define ALLPERMS (S_ISUID | S_ISGID | S_ISVTX | MODE_RWX)

static int _chmod(inode_t* inode, mode_t mode)
{
    int ret = 0;
    myst_thread_t* self = myst_thread_self();

    if (!inode)
        ERAISE(-EINVAL);

    inode->mode &= ~ALLPERMS;
    inode->mode |= (mode & ALLPERMS);

    /* If not privileged and inode not in thread's primary or supplementary
     * groups, drop S_ISGID bit */
    if ((inode->mode & S_ISGID) && self->euid != 0 &&
        (check_thread_group_membership(inode->gid) != 0))
    {
        inode->mode &= ~S_ISGID;
    }

    _update_timestamps(inode, CHANGE);

done:
    return ret;
}

static int _fs_chmod(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    struct locals
    {
        inode_t* inode;
        char suffix[PATH_MAX];
    }* locals = NULL;
    myst_fs_t* tfs = NULL;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Check if path exists */
    ECHECK(_path_to_inode(
        ramfs, pathname, true, NULL, &locals->inode, locals->suffix, &tfs));
    if (tfs)
    {
        // delegate operation to target filesystem.
        ECHECK((ret = tfs->fs_chmod(tfs, locals->suffix, mode)));
        goto done;
    }

    ECHECK(_chmod(locals->inode, mode));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_fchmod(myst_fs_t* fs, myst_file_t* file, mode_t mode)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !file)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    assert(_inode_valid(file->shared->inode));
    ECHECK(_chmod(file->shared->inode, mode));

done:
    return ret;
}

static int _fs_fsync_and_fdatasync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !file)
        ERAISE(-EINVAL);

    if (file->shared->access == O_PATH)
        ERAISE(-EBADF);

    // ramfs being a in-memory fs, treat fsync and datasync as NOP

done:
    return ret;
}

static int _fs_release_tree(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t *parent, *self;
    struct locals
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_path_to_inode(ramfs, pathname, true, &parent, &self, NULL, NULL));

    if (!_inode_valid(parent) || !_inode_valid(self))
        ERAISE(-EINVAL);

    /* Release all inodes in the sub-tree under self*/
    {
        int type, mode = self->mode;
        if (S_ISDIR(mode))
            type = DT_DIR;
        else if (S_ISREG(mode) || S_ISCHR(mode))
            type = DT_REG;
        else if (S_ISLNK(mode))
            type = DT_LNK;
        else
        {
            ERAISE(-EINVAL);
        }

        _inode_release_all(ramfs, parent, self, type);
    }

    /* Remove directory entry from parent */
    {
        /* Get the parent inode */
        ECHECK(_split_path(pathname, locals->dirname, locals->basename));

        /* Find and remove the parent's directory entry */
        {
            ECHECK(_inode_remove_dirent(parent, locals->basename));
        }
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_file_data_start_addr(
    myst_fs_t* fs,
    myst_file_t* file,
    void** addr_out)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (_is_shmfs(ramfs))
    {
        if (!addr_out)
            ERAISE(-EINVAL);

        *addr_out = NULL;

        /* memory for shm files are allocated on first ftruncate, or via writing
        to the file(Pytorch multiprocessing does this). Fail if process mmaps
        before that */
        if (!(*addr_out = file->shared->inode->buf.data))
            ERAISE(-ENOEXEC);
    }
    else
    {
        ERAISE(-ENOTSUP);
    }

done:
    return ret;
}

static int _fs_file_mapping_notify(
    myst_fs_t* fs,
    myst_file_t* file,
    bool active)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (_is_shmfs(ramfs))
    {
        inode_t* inode = file->shared->inode;
        ECHECK(myst_buf_set_mmap_active(&inode->buf, active));

        // Cleanup only if there are no active mmaps,
        // inode has been unlinked, and no file handles
        if (!active && !inode->nlink && !inode->nopens)
        {
            _inode_free(ramfs, inode);
        }
    }
    else
    {
        ERAISE(-ENOTSUP);
    }

done:
    return ret;
}

static int _init_ramfs(
    myst_mount_resolve_callback_t resolve_cb,
    myst_fs_t** fs_out,
    ramfs_minor_num_t device_num)
{
    int ret = 0;
    ramfs_t* ramfs = NULL;
    // clang-format off
    static myst_fs_t _base =
    {
        {
            .fd_read = (void*)_fs_read,
            .fd_write = (void*)_fs_write,
            .fd_readv = (void*)_fs_readv,
            .fd_writev = (void*)_fs_writev,
            .fd_fstat = (void*)_fs_fstat,
            .fd_fcntl = (void*)_fs_fcntl,
            .fd_ioctl = (void*)_fs_ioctl,
            .fd_dup = (void*)_fs_dup,
            .fd_close = (void*)_fs_close,
            .fd_target_fd = (void*)_fs_target_fd,
            .fd_get_events = (void*)_fs_get_events,
        },
        .fs_release = _fs_release,
        .fs_mount = _fs_mount,
        .fs_creat = _fs_creat,
        .fs_open = _fs_open,
        .fs_lseek = _fs_lseek,
        .fs_read = _fs_read,
        .fs_write = _fs_write,
        .fs_pread = _fs_pread,
        .fs_pwrite = _fs_pwrite,
        .fs_readv = _fs_readv,
        .fs_writev = _fs_writev,
        .fs_close = _fs_close,
        .fs_access = _fs_access,
        .fs_stat = _fs_stat,
        .fs_lstat = _fs_lstat,
        .fs_fstat = _fs_fstat,
        .fs_link = _fs_link,
        .fs_unlink = _fs_unlink,
        .fs_rename = _fs_rename,
        .fs_truncate = _fs_truncate,
        .fs_ftruncate = _fs_ftruncate,
        .fs_mkdir = _fs_mkdir,
        .fs_rmdir = _fs_rmdir,
        .fs_getdents64 = _fs_getdents64,
        .fs_readlink = _fs_readlink,
        .fs_symlink = _fs_symlink,
        .fs_realpath = _fs_realpath,
        .fs_fcntl = _fs_fcntl,
        .fs_ioctl = _fs_ioctl,
        .fs_dup = _fs_dup,
        .fs_target_fd = _fs_target_fd,
        .fs_get_events = _fs_get_events,
        .fs_statfs = _fs_statfs,
        .fs_fstatfs = _fs_fstatfs,
        .fs_futimens = _fs_futimens,
        .fs_chown = _fs_chown,
        .fs_fchown = _fs_fchown,
        .fs_lchown = _fs_lchown,
        .fs_chmod = _fs_chmod,
        .fs_fchmod = _fs_fchmod,
        .fs_fdatasync = _fs_fsync_and_fdatasync,
        .fs_fsync = _fs_fsync_and_fdatasync,
        .fs_release_tree = _fs_release_tree,
        .fs_file_data_start_addr = _fs_file_data_start_addr,
        .fs_file_mapping_notify = _fs_file_mapping_notify,
    };
    // clang-format on
    inode_t* root_inode = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (!fs_out)
        ERAISE(-EINVAL);

    if (!(ramfs = calloc(1, sizeof(ramfs_t))))
        ERAISE(-ENOMEM);

    ECHECK(_inode_new(ramfs, NULL, "/", (S_IFDIR | MODE_RWX), &root_inode));

    ramfs->magic = RAMFS_MAGIC;
    ramfs->base = _base;
    ramfs->root = root_inode;
    ramfs->resolve = resolve_cb;
    myst_strlcpy(ramfs->target, "/", sizeof(ramfs->target));
    ramfs->device_num = device_num;
    root_inode = NULL;

    *fs_out = &ramfs->base;
    ramfs = NULL;

done:

    if (ramfs)
        free(ramfs);

    if (root_inode)
        free(root_inode);

    return ret;
}

int myst_init_ramfs(
    myst_mount_resolve_callback_t resolve_cb,
    myst_fs_t** fs_out,
    ramfs_minor_num_t device_num)
{
    int ret = 0;
    myst_fs_t* ramfs = NULL;
    myst_fs_t* lockfs;

    /* always wrap ramfs inside lockfs */
    ECHECK(_init_ramfs(resolve_cb, &ramfs, device_num));
    ECHECK(myst_lockfs_init(ramfs, &lockfs));
    ((ramfs_t*)ramfs)->lockfs = lockfs;
    ramfs = NULL;
    *fs_out = lockfs;

done:

    if (ramfs)
        (*ramfs->fs_release)(ramfs);

    return ret;
}

static ramfs_t* _ramfs(myst_fs_t* fs)
{
    myst_fs_t* target = myst_lockfs_target(fs);
    return target ? (ramfs_t*)target : (ramfs_t*)fs;
}

int myst_ramfs_set_buf(
    myst_fs_t* fs,
    const char* pathname,
    const void* buf,
    size_t buf_size)
{
    ramfs_t* ramfs = _ramfs(fs);
    inode_t* inode = NULL;
    int ret = 0;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!pathname)
        ERAISE(-EINVAL);

    if (!buf && buf_size)
        ERAISE(-EINVAL);

    ECHECK(_path_to_inode(ramfs, pathname, true, NULL, &inode, NULL, NULL));

    if (inode->buf.data != inode->data)
        myst_buf_clear(&inode->buf);

    inode->data = buf;
    inode->buf.data = (void*)buf;
    inode->buf.size = buf_size;

done:

    return ret;
}

int myst_create_virtual_file(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_vcallback_t v_cb)
{
    int ret = 0;
    ramfs_t* ramfs = _ramfs(fs);

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!pathname || !mode)
        ERAISE(-EINVAL);

    /* create an empty file */
    if (S_ISREG(mode) || S_ISCHR(mode))
    {
        myst_file_t* file = NULL;
        ECHECK(
            fs->fs_open(fs, pathname, O_RDONLY | O_CREAT, mode, NULL, &file));
        ECHECK(fs->fs_close(fs, file));
    }
    else if (S_ISLNK(mode))
    {
        /* pass empty target to symlink */
        char target = '\0';
        ECHECK(fs->fs_symlink(fs, &target, pathname));
    }
    else
    {
        ERAISE(-EINVAL);
    }

    /* inject vcallback into the inode */
    {
        inode_t* inode = NULL;
        ECHECK(
            _path_to_inode(ramfs, pathname, false, NULL, &inode, NULL, NULL));

        inode->v_cb = v_cb;
    }

    ret = 0;

done:

    return ret;
}

int myst_read_stateful_virtual_file(
    myst_file_t* file,
    void* buf,
    size_t buf_size)
{
    int ret = 0;
    size_t len = buf_size;

    myst_spin_lock(&file->shared->vbuf_lock);
    if (file->shared->vbuf.size < len)
        len = file->shared->vbuf.size;

    memcpy(buf, file->shared->vbuf.data, len);

    myst_buf_remove(&file->shared->vbuf, 0, len);

    ret = len;

    myst_spin_unlock(&file->shared->vbuf_lock);
    return ret;
}

int myst_write_stateful_virtual_file(
    myst_file_t* file,
    const void* buf,
    size_t buf_size)
{
    int ret = 0;
    myst_spin_lock(&file->shared->vbuf_lock);
    ret = myst_buf_append(&file->shared->vbuf, buf, buf_size);
    myst_spin_unlock(&file->shared->vbuf_lock);
    return ret;
}

/*
 * Overrides for special filesystems based on ramfs.
 * For eg: devfs, procfs
 */

static int _einval_override(myst_fs_t* fs, myst_file_t* file)
{
    (void)fs;
    (void)file;

    return -EINVAL;
}

int set_overrides_for_special_fs(myst_fs_t* fs)
{
    int ret = 0;

    if (!fs)
        ERAISE(-EINVAL);

    ramfs_t* ramfs = _ramfs(fs);

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    ramfs->base.fs_fdatasync = ramfs->base.fs_fsync = _einval_override;

done:
    return ret;
}
