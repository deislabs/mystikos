#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <libos/backtrace.h>
#include <libos/buf.h>
#include <libos/bufu64.h>
#include <libos/eraise.h>
#include <libos/fs.h>
#include <libos/id.h>
#include <libos/panic.h>
#include <libos/paths.h>
#include <libos/printf.h>
#include <libos/ramfs.h>
#include <libos/realpath.h>
#include <libos/round.h>
#include <libos/strings.h>
#include <libos/trace.h>

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
    libos_fs_t base;
    uint64_t magic;
    inode_t* root;
    char target[PATH_MAX]; /* the directory this file system is mounted on */
} ramfs_t;

static bool _ramfs_valid(const ramfs_t* ramfs)
{
    return ramfs && ramfs->magic == RAMFS_MAGIC;
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
    uint32_t mode;    /* Type and mode */
    size_t nlink;     /* number of hard links to this inode (excludes ".") */
    size_t nopens;    /* number of times file is currently opened */
    libos_buf_t buf;  /* file or directory data */
    const void* data; /* set by libos_ramfs_set_buf() */
};

static bool _inode_valid(const inode_t* inode)
{
    return inode && inode->magic == INODE_MAGIC;
}

static void _inode_free(inode_t* inode)
{
    if (inode)
    {
        if (inode->buf.data != inode->data)
            libos_buf_release(&inode->buf);
        memset(inode, 0xdd, sizeof(inode_t));
        free(inode);
    }
}

/* Note: does not update nlink */
static int _inode_add_dirent(
    inode_t* dir,
    inode_t* inode,
    uint8_t type, /* DT_REG or DT_DIR */
    const char* name)
{
    int ret = 0;

    if (!_inode_valid(dir) || !_inode_valid(inode) || !name)
        ERAISE(-EINVAL);

    if (type != DT_REG && type != DT_DIR && type != DT_LNK)
        ERAISE(-EINVAL);

    /* Append the new directory entry */
    {
        struct dirent ent = {
            .d_ino = (ino_t)inode,
            .d_off = (off_t)dir->buf.size,
            .d_reclen = sizeof(struct dirent),
            .d_type = type,
        };

        if (LIBOS_STRLCPY(ent.d_name, name) >= sizeof(ent.d_name))
            ERAISE(-ENAMETOOLONG);

        if (libos_buf_append(&dir->buf, &ent, sizeof(ent)) != 0)
            ERAISE(-ENOMEM);
    }

done:
    return ret;
}

static bool _inode_is_empty_dir(const inode_t* inode)
{
    /* empty directories have two entries: "." and ".." */
    const size_t empty_size = (2 * sizeof(struct dirent));
    return inode && S_ISDIR(inode->mode) && inode->buf.size == empty_size;
}

static int _inode_new(
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

    /* The root directory is its own parent */
    if (!parent)
        parent = inode;

    /* If new inode is a directory, add the "." and ".." elements */
    if (S_ISDIR(mode))
    {
        /* Add the "." entry */
        ECHECK(_inode_add_dirent(inode, inode, DT_DIR, "."));

        /* Add the ".." entry */
        ECHECK(_inode_add_dirent(inode, parent, DT_DIR, ".."));
    }

    /* Add this inode to the parent's directory table (if not root) */
    if (parent != inode)
    {
        uint8_t type;

        if (S_ISDIR(mode))
            type = DT_DIR;
        else if (S_ISREG(mode))
            type = DT_REG;
        else if (S_ISLNK(mode))
            type = DT_LNK;
        else
        {
            ERAISE(-EINVAL);
        }

        ECHECK(_inode_add_dirent(parent, inode, type, name));
        parent->nlink++;
    }

    if (inode_out)
        *inode_out = inode;

    inode = NULL;

done:

    if (inode)
        _inode_free(inode);

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
static void _inode_release_all(inode_t* parent, inode_t* inode, uint8_t d_type)
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
                _inode_release_all(inode, child, ent->d_type);
        }
    }

    /* If not the root inode */
    if (parent)
        parent->nlink--;

    if (--inode->nlink == 0)
        _inode_free(inode);
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

            if (libos_buf_remove(&inode->buf, pos, size) != 0)
                ERAISE(-ENOMEM);

            index = i;
            break;
        }
    }

    if (index == (size_t)-1)
        ERAISE(-ENOENT);

    /* Adjust d_off for entries following the deleted entry */
    for (size_t i = index + 1; i < nents; i++)
    {
        ents[i].d_off -= (off_t)sizeof(struct dirent);
    }

done:
    return ret;
}

static const char* _inode_target(const inode_t* inode)
{
    return (const char*)inode->buf.data;
}

/*
**==============================================================================
**
** libos_file_t
**
**==============================================================================
*/

#define FILE_MAGIC 0xdfe1d5c160064f8e

struct libos_file
{
    uint64_t magic;
    inode_t* inode;
    size_t offset;      /* the current file offset (files) */
    uint32_t access;    /* (O_RDONLY | O_RDWR | O_WRONLY) */
    uint32_t operating; /* (O_RDONLY | O_RDWR | O_WRONLY) */
    char realpath[PATH_MAX];
};

static bool _file_valid(const libos_file_t* file)
{
    return file && file->magic == FILE_MAGIC;
}

static void* _file_data(const libos_file_t* file)
{
    return file->inode->buf.data;
}

static size_t _file_size(const libos_file_t* file)
{
    return file->inode->buf.size;
}

static void* _file_current(libos_file_t* file)
{
    return (uint8_t*)_file_data(file) + file->offset;
}

static void* _file_at(libos_file_t* file, size_t offset)
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

static int _split_path(
    const char* path,
    char dirname[PATH_MAX],
    char basename[PATH_MAX])
{
    int ret = 0;
    char* slash;

    /* Reject paths that are too long. */
    if (strlen(path) >= PATH_MAX)
        ERAISE(-EINVAL);

    /* Reject paths that are not absolute */
    if (path[0] != '/')
        ERAISE(-EINVAL);

    /* Handle root directory up front */
    if (strcmp(path, "/") == 0)
    {
        libos_strlcpy(dirname, "/", PATH_MAX);
        libos_strlcpy(basename, "/", PATH_MAX);
        goto done;
    }

    /* This cannot fail (prechecked) */
    if (!(slash = strrchr(path, '/')))
        ERAISE(-EINVAL);

    /* If path ends with '/' character */
    if (!slash[1])
        ERAISE(-EINVAL);

    /* Split the path */
    {
        if (slash == path)
        {
            libos_strlcpy(dirname, "/", PATH_MAX);
        }
        else
        {
            size_t index = (size_t)(slash - path);
            libos_strlcpy(dirname, path, PATH_MAX);

            if (index < PATH_MAX)
                dirname[index] = '\0';
            else
                dirname[PATH_MAX - 1] = '\0';
        }

        libos_strlcpy(basename, slash + 1, PATH_MAX);
    }

done:
    return ret;
}

static int _path_to_inode_recursive(
    ramfs_t* ramfs,
    const char* path,
    inode_t* parent,
    bool follow,
    inode_t** parent_out,
    inode_t** inode_out,
    char realpath[PATH_MAX])
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
            libos_strlcpy(realpath, "/", PATH_MAX);

        *inode_out = inode;

        ret = 0;
        goto done;
    }

    /* Split the path into tokens */
    ECHECK(libos_strsplit(path, "/", &toks, &ntoks));

    /* search for the inode */
    {
        for (size_t i = 0; i < ntoks; i++)
        {
            inode_t* p;

            if (!(p = _inode_find_child(parent, toks[i])))
                ERAISE_QUIET(-ENOENT);

            if (!S_ISLNK(p->mode))
            {
                if (realpath)
                {
                    if (libos_strlcat(realpath, "/", PATH_MAX) >= PATH_MAX)
                        ERAISE_QUIET(-ENAMETOOLONG);

                    if (libos_strlcat(realpath, toks[i], PATH_MAX) >= PATH_MAX)
                        ERAISE_QUIET(-ENAMETOOLONG);
                }
            }

            if (S_ISLNK(p->mode) && (follow || i + 1 != ntoks))
            {
                const char* target = _inode_target(p);

                /* ATTN: Handle case where ramfs not mounted on "/" */
                if (*target == '/')
                {
                    if (realpath)
                        *realpath = '\0';

                    parent = ramfs->root;
                }

                ECHECK(_path_to_inode_recursive(
                    ramfs, target, parent, true, &parent, &p, realpath));

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
    char realpath_out[PATH_MAX])
{
    int ret = 0;
    char realpath[PATH_MAX] = {'\0'};

    ECHECK(_path_to_inode_recursive(
        ramfs,
        path,
        ramfs->root,
        follow,
        parent_out,
        inode_out,
        realpath_out ? realpath : NULL));

    if (realpath_out)
        ECHECK(libos_normalize(realpath, realpath_out, PATH_MAX));

done:
    return ret;
}

static int _path_to_inode(
    ramfs_t* ramfs,
    const char* path,
    bool follow,
    inode_t** parent_out,
    inode_t** inode_out)
{
    return _path_to_inode_realpath(
        ramfs, path, follow, parent_out, inode_out, NULL);
}

/*
**==============================================================================
**
** interface:
**
**==============================================================================
*/

static int _fs_release(libos_fs_t* fs)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    _inode_release_all(NULL, ramfs->root, DT_DIR);

    free(ramfs);

done:
    return ret;
}

static int _fs_mount(libos_fs_t* fs, const char* target)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !target)
        ERAISE(-EINVAL);

    if (strlen(target) >= sizeof(ramfs->target))
        ERAISE(-ENAMETOOLONG);

    libos_strlcpy(ramfs->target, target, sizeof(ramfs->target));

done:
    return ret;
}

static int _fs_creat(
    libos_fs_t* fs,
    const char* pathname,
    mode_t mode,
    libos_file_t** file)
{
    int ret = 0;
    const int flags = O_CREAT | O_WRONLY | O_TRUNC;

    if (!fs)
        ERAISE(-EINVAL);

    ERAISE((*fs->fs_open)(fs, pathname, flags, mode, file));

done:
    return ret;
}

static int _fs_open(
    libos_fs_t* fs,
    const char* pathname,
    int flags,
    mode_t mode,
    libos_file_t** file_out)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode = NULL;
    libos_file_t* file = NULL;
    int ret = 0;
    int errnum;
    bool is_i_new = false;

    if (file_out)
        *file_out = NULL;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!pathname)
        ERAISE(-EINVAL);

    if (!file_out)
        ERAISE(-EINVAL);

    /* Create the file object */
    if (!(file = calloc(1, sizeof(libos_file_t))))
        ERAISE(-ENOMEM);

    errnum = _path_to_inode(ramfs, pathname, true, NULL, &inode);

    /* If the file already exists */
    if (errnum == 0)
    {
        if ((flags & O_CREAT) && (flags & O_EXCL))
            ERAISE(-EEXIST);

        if ((flags & O_DIRECTORY) && !S_ISDIR(inode->mode))
            ERAISE(-ENOTDIR);

        if ((flags & O_TRUNC))
            libos_buf_clear(&inode->buf);

        if ((flags & O_APPEND))
            file->offset = inode->buf.size;
    }
    else if (errnum == -ENOENT)
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
        inode_t* parent;

        is_i_new = true;

        if (!(flags & O_CREAT))
            ERAISE(-ENOENT);

        /* Split the path into parent directory and file name */
        ECHECK(_split_path(pathname, dirname, basename));

        /* Get the inode of the parent directory. */
        ECHECK(_path_to_inode(ramfs, dirname, true, NULL, &parent));

        /* Create the new file inode */
        ECHECK(_inode_new(parent, basename, (S_IFREG | mode), &inode));
    }
    else
    {
        ERAISE(-errnum);
    }

    /* Initialize the file */
    file->magic = FILE_MAGIC;
    file->inode = inode;
    file->access = (flags & (O_RDONLY | O_RDWR | O_WRONLY));
    file->operating = (flags & O_APPEND);
    inode->nopens++;

    /* Get the realpath of this file */
    ECHECK(_path_to_inode_realpath(
        ramfs, pathname, true, NULL, &inode, file->realpath));

    assert(_file_valid(file));

    *file_out = file;
    file = NULL;
    inode = NULL;

done:

    if (inode && is_i_new)
        free(inode);

    if (file)
        free(file);

    return ret;
}

static off_t _fs_lseek(
    libos_fs_t* fs,
    libos_file_t* file,
    off_t offset,
    int whence)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    off_t ret = 0;
    off_t new_offset;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    switch (whence)
    {
        case SEEK_SET:
        {
            new_offset = offset;
            break;
        }
        case SEEK_CUR:
        {
            new_offset = (off_t)file->offset + offset;
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

    /* ATTN: support seeking beyond the end of file */

    /* Check whether new offset if out of range */
    if (new_offset < 0 || new_offset > (off_t)_file_size(file))
        ERAISE(-EINVAL);

    file->offset = (size_t)new_offset;

    ret = new_offset;

done:
    return ret;
}

static ssize_t _fs_read(
    libos_fs_t* fs,
    libos_file_t* file,
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

    /* reading zero bytes is okay */
    if (!count)
        goto done;

    /* Verify that the offset is in bounds */
    if (file->offset > _file_size(file))
        ERAISE(-EINVAL);

    /* Read count bytes from the file or directory */
    {
        size_t remaining = _file_size(file) - file->offset;

        if (remaining == 0)
        {
            /* end of file */
            goto done;
        }

        n = (count < remaining) ? count : remaining;
        memcpy(buf, _file_current(file), n);
        file->offset += n;
    }

    ret = (ssize_t)n;

done:
    return ret;
}

static ssize_t _fs_write(
    libos_fs_t* fs,
    libos_file_t* file,
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

    /* Verify that the offset is in bounds */
    if (file->offset > _file_size(file))
        ERAISE(-EINVAL);

    /* Write count bytes to the file or directory */
    {
        size_t new_offset = file->offset + count;

        if (new_offset > _file_size(file))
        {
            if (libos_buf_resize(&file->inode->buf, new_offset) != 0)
                ERAISE(-ENOMEM);
        }

        memcpy(_file_current(file), buf, count);
        file->offset = new_offset;
    }

    ret = (ssize_t)count;

done:
    return ret;
}

static ssize_t _fs_pread(
    libos_fs_t* fs,
    libos_file_t* file,
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

    ret = (ssize_t)n;

done:
    return ret;
}

static ssize_t _fs_pwrite(
    libos_fs_t* fs,
    libos_file_t* file,
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

    /* Verify that the offset is in bounds */
    if ((size_t)offset > _file_size(file))
        ERAISE(-EINVAL);

    /* Write count bytes to the file or directory */
    {
        size_t new_offset = (size_t)offset + count;

        if (new_offset > _file_size(file))
        {
            if (libos_buf_resize(&file->inode->buf, new_offset) != 0)
                ERAISE(-ENOMEM);
        }

        memcpy(_file_at(file, (size_t)offset), buf, count);
    }

    ret = (ssize_t)count;

done:
    return ret;
}

static ssize_t _fs_readv(
    libos_fs_t* fs,
    libos_file_t* file,
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
    libos_fs_t* fs,
    libos_file_t* file,
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

static int _fs_close(libos_fs_t* fs, libos_file_t* file)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    assert(file->inode);
    assert(_inode_valid(file->inode));
    assert(file->inode->nopens > 0);

    file->inode->nopens--;

    if (file->inode->nopens == 0 && file->inode->nlink == 0)
    {
        _inode_free(file->inode);
    }

    memset(file, 0xdd, sizeof(libos_file_t));
    free(file);

done:
    return ret;
}

static int _fs_access(libos_fs_t* fs, const char* pathname, int mode)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    if (mode != F_OK && !(mode & (R_OK | W_OK | X_OK)))
        ERAISE(-EINVAL);

    /* Get the inode for pathname */
    ECHECK(_path_to_inode(ramfs, pathname, true, NULL, &inode));

    if (mode == F_OK)
        goto done;

    if ((mode & R_OK) && !(inode->mode & S_IRUSR))
        ERAISE(-EACCES);

    if ((mode & W_OK) && !(inode->mode & S_IWUSR))
        ERAISE(-EACCES);

    if ((mode & X_OK) && !(inode->mode & S_IXUSR))
        ERAISE(-EACCES);

done:

    return ret;
}

static int _stat(inode_t* inode, struct stat* statbuf)
{
    int ret = 0;
    struct stat buf;

    if (!_inode_valid(inode) || !statbuf)
        ERAISE(-EINVAL);

    memset(&buf, 0, sizeof(buf));
    buf.st_dev = 0;
    buf.st_ino = (ino_t)inode;
    buf.st_mode = inode->mode;
    buf.st_nlink = inode->nlink;
    buf.st_uid = LIBOS_DEFAULT_UID;
    buf.st_gid = LIBOS_DEFAULT_GID;
    buf.st_rdev = 0;
    buf.st_size = (off_t)inode->buf.size;
    buf.st_blksize = BLKSIZE;
    buf.st_blocks = libos_round_up_off(buf.st_size, BLKSIZE) / BLKSIZE;
    memset(&buf.st_atim, 0, sizeof(buf.st_atim)); /* ATTN: unsupported */
    memset(&buf.st_mtim, 0, sizeof(buf.st_mtim)); /* ATTN: unsupported */
    memset(&buf.st_ctim, 0, sizeof(buf.st_ctim)); /* ATTN: unsupported */

    *statbuf = buf;

done:
    return ret;
}

static int _fs_stat(libos_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;

    if (!_ramfs_valid(ramfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    ECHECK(_path_to_inode(ramfs, pathname, true, NULL, &inode));
    ERAISE(_stat(inode, statbuf));

done:
    return ret;
}

static int _fs_lstat(libos_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;

    if (!_ramfs_valid(ramfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    ECHECK(_path_to_inode(ramfs, pathname, false, NULL, &inode));
    ERAISE(_stat(inode, statbuf));

done:
    return ret;
}

static int _fs_fstat(libos_fs_t* fs, libos_file_t* file, struct stat* statbuf)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !statbuf)
        ERAISE(-EINVAL);

    assert(_inode_valid(file->inode));
    ERAISE(_stat(file->inode, statbuf));

done:
    return ret;
}

static int _fs_link(libos_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* old_inode;
    inode_t* new_parent;
    char new_dirname[PATH_MAX];
    char new_basename[PATH_MAX];

    if (!_ramfs_valid(ramfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    /* Find the inode for oldpath */
    ECHECK(_path_to_inode(ramfs, oldpath, true, NULL, &old_inode));

    /* oldpath must not be a directory */
    if (S_ISDIR(old_inode->mode))
        ERAISE(-EPERM);

    /* Find the parent inode of newpath */
    ECHECK(_split_path(newpath, new_dirname, new_basename));
    ECHECK(_path_to_inode(ramfs, new_dirname, true, NULL, &new_parent));

    /* Fail if newpath already exists */
    if (_inode_find_child(new_parent, new_basename) != NULL)
        ERAISE(-EEXIST);

    /* Add the directory entry for the newpath */
    _inode_add_dirent(new_parent, old_inode, DT_REG, new_basename);

    /* Increment the new parent's link count */
    new_parent->nlink++;

    /* Increment the file's link count */
    old_inode->nlink++;

done:
    return ret;
}

static int _fs_unlink(libos_fs_t* fs, const char* pathname)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    char dirname[PATH_MAX];
    char basename[PATH_MAX];
    inode_t* parent;
    inode_t* inode;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    /* Get the inode for pathname */
    ECHECK(_path_to_inode(ramfs, pathname, false, NULL, &inode));

    /* pathname must not be a directory */
    if (S_ISDIR(inode->mode))
        ERAISE(-EPERM);

    /* Get the parent inode */
    ECHECK(_split_path(pathname, dirname, basename));
    ECHECK(_path_to_inode(ramfs, dirname, true, NULL, &parent));

    inode->nlink--;
    /* Find and remove the parent's directory entry */
    ECHECK(_inode_remove_dirent(parent, basename));
    parent->nlink--;

    // Delete the inode immediately if it's a symbolic link
    // or nobody owned. The deletion is delayed to _fs_close
    // if file is still linked or opened by someone.
    if (S_ISLNK(inode->mode) ||
        (inode->nlink == 0 && inode->nopens == 0))
    {
        _inode_free(inode);
    }

done:
    return ret;
}

static int _fs_rename(libos_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    char old_dirname[PATH_MAX];
    char old_basename[PATH_MAX];
    char new_dirname[PATH_MAX];
    char new_basename[PATH_MAX];
    inode_t* old_parent = NULL;
    inode_t* old_inode = NULL;
    inode_t* new_parent = NULL;
    inode_t* new_inode = NULL;

    /* ATTN: check attempt to make subdirectory a directory of itself */
    /* ATTN: check where newpath contains a prefix of oldpath */

    if (!_ramfs_valid(ramfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    /* Split oldpath and newpath */
    ECHECK(_split_path(newpath, new_dirname, new_basename));
    ECHECK(_split_path(oldpath, old_dirname, old_basename));

    /* Find the oldpath inode */
    ECHECK(_path_to_inode(ramfs, oldpath, true, &old_parent, &old_inode));

    /* Get the parent of newpath */
    ECHECK(_path_to_inode(ramfs, new_dirname, true, NULL, &new_parent));

    /* Get the newpath inode (if any) */
    new_inode = _inode_find_child(new_parent, new_basename);

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
    ECHECK(_inode_remove_dirent(old_parent, old_basename));
    old_parent->nlink--;

    /* Add the newpath directory entry */
    _inode_add_dirent(new_parent, old_inode, DT_REG, new_basename);
    new_parent->nlink++;

    /* Dereference the new inode (if any) */
    if (new_inode && --new_inode->nlink == 0)
        _inode_free(new_inode);

done:
    return ret;
}

static int _fs_truncate(libos_fs_t* fs, const char* path, off_t length)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;

    if (!_ramfs_valid(ramfs) || !path || length < 0)
        ERAISE(-EINVAL);

    ECHECK(_path_to_inode(ramfs, path, true, NULL, &inode));

    if (S_ISDIR(inode->mode))
        ERAISE(-EISDIR);

    if (libos_buf_resize(&inode->buf, (size_t)length) != 0)
        ERAISE(-ENOMEM);

done:
    return ret;
}

static int _fs_ftruncate(libos_fs_t* fs, libos_file_t* file, off_t length)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || length < 0)
        ERAISE(-EINVAL);

    if (S_ISDIR(file->inode->mode))
        ERAISE(-EISDIR);

    if (libos_buf_resize(&file->inode->buf, (size_t)length) != 0)
        ERAISE(-ENOMEM);

done:
    return ret;
}

static int _fs_mkdir(libos_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    char dirname[PATH_MAX];
    char basename[PATH_MAX];
    inode_t* parent;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    ECHECK(_split_path(pathname, dirname, basename));
    ECHECK(_path_to_inode(ramfs, dirname, true, NULL, &parent));

    /* The parent must be a directory */
    if (!S_ISDIR(parent->mode))
        ERAISE(-ENOTDIR);

    /* Check whether the pathname already exists */
    if (_inode_find_child(parent, basename) != NULL)
        ERAISE(-EEXIST);

    /* create the directory */
    ERAISE(_inode_new(parent, basename, (S_IFDIR | mode), NULL));

done:
    return ret;
}

static int _fs_rmdir(libos_fs_t* fs, const char* pathname)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    char dirname[PATH_MAX];
    char basename[PATH_MAX];
    inode_t* parent;
    inode_t* child;

    if (!_ramfs_valid(ramfs) || !pathname)
        ERAISE(-EINVAL);

    /* Get the child inode */
    ECHECK(_path_to_inode(ramfs, pathname, true, NULL, &child));

    /* The child must be a directory */
    if (!S_ISDIR(child->mode))
        ERAISE(-ENOTDIR);

    /* Make sure the directory has no children */
    if (child->buf.size > (2 * sizeof(struct dirent)))
        ERAISE(-ENOTEMPTY);

    /* Get the parent inode */
    ECHECK(_split_path(pathname, dirname, basename));
    ECHECK(_path_to_inode(ramfs, dirname, true, NULL, &parent));

    /* Find and remove the parent's directory entry */
    ECHECK(_inode_remove_dirent(parent, basename));
    parent->nlink--;

    /* Decrement the number of links */
    child->nlink--;

    /* If no more links to this inode, then free it */
    if (child->nlink == 0)
        _inode_free(child);

done:
    return ret;
}

static int _fs_getdents64(
    libos_fs_t* fs,
    libos_file_t* file,
    struct dirent* dirp,
    size_t count)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    size_t n = count / sizeof(struct dirent);
    size_t bytes = 0;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !dirp)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    for (size_t i = 0; i < n; i++)
    {
        struct dirent ent;
        ssize_t r;

        /* Read next entry and break on end-of-file */
        if ((r = _fs_read(fs, file, &ent, sizeof(ent))) == 0)
            break;

        /* Fail if exactly one entry was not read */
        if (r != sizeof(ent))
            libos_panic("unexpected");

        *dirp = ent;
        bytes += sizeof(struct dirent);
        dirp++;
    }

    ret = (int)bytes;

done:
    return ret;
}

ssize_t _fs_readlink(
    libos_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    ssize_t ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode;

    if (!_ramfs_valid(ramfs) || !pathname || !buf || !bufsiz)
        ERAISE(-EINVAL);

    /* Get the inode for pathname */
    ECHECK(_path_to_inode(ramfs, pathname, false, NULL, &inode));

    if (!S_ISLNK(inode->mode))
        ERAISE(-EINVAL);

    assert(inode->buf.data);
    assert(inode->buf.size);

    if (!inode->buf.data || !inode->buf.size)
        ERAISE(-EINVAL);

    ret = (ssize_t)libos_strlcpy(buf, (char*)inode->buf.data, bufsiz);

done:

    return ret;
}

static int _fs_symlink(libos_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode = NULL;
    inode_t* parent = NULL;
    char dirname[PATH_MAX];
    char basename[PATH_MAX];

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!target || !linkpath)
        ERAISE(-EINVAL);

    /* Split linkpath into directory and filename */
    ECHECK(_split_path(linkpath, dirname, basename));

    /* Get the inode of the parent directory */
    ECHECK(_path_to_inode(ramfs, dirname, true, NULL, &parent));

    /* Create the new link inode */
    ECHECK(_inode_new(parent, basename, (S_IFLNK | 0777), &inode));

    /* Write the target name into the link inode */
    if (libos_buf_append(&inode->buf, target, strlen(target) + 1) != 0)
        ERAISE(-ENOMEM);

done:

    return ret;
}

static int _fs_realpath(
    libos_fs_t* fs,
    libos_file_t* file,
    char* buf,
    size_t size)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file) || !buf || !size)
        ERAISE(-EINVAL);

    if (strcmp(ramfs->target, "/") == 0)
    {
        if (libos_strlcpy(buf, file->realpath, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        int n = snprintf(buf, size, "%s%s", ramfs->target, file->realpath);

        if (n < 0 || n >= (int)size)
            ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

static int _fs_fcntl(libos_fs_t* fs, libos_file_t* file, int cmd, long arg)
{
    int ret = 0;
    ramfs_t* ramfs = (ramfs_t*)fs;

    if (!_ramfs_valid(ramfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (cmd == F_SETFD && arg == FD_CLOEXEC)
    {
        /* FD_CLOEXEC can be safely ignored (fork/exec not supported) */
        goto done;
    }

    /* Get the file-access-mode and the file-status-flags */
    if (cmd == F_GETFL)
    {
        ret = (int)(file->access | file->operating);
        goto done;
    }

    if (cmd == F_SETLKW)
    {
        /* ATTN: silently ignoring locking for now */
        goto done;
    }

    ERAISE(-ENOTSUP);

done:
    return ret;
}

int libos_init_ramfs(libos_fs_t** fs_out)
{
    int ret = 0;
    ramfs_t* ramfs = NULL;
    // clang-format off
    static libos_fs_t _base =
    {
        {
            .fd_read = (void*)_fs_read,
            .fd_write = (void*)_fs_write,
            .fd_readv = (void*)_fs_readv,
            .fd_writev = (void*)_fs_writev,
            .fd_fstat = (void*)_fs_fstat,
            .fd_fcntl = (void*)_fs_fcntl,
            .fd_close = (void*)_fs_close,
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
    };
    // clang-format on
    inode_t* root_inode = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (!fs_out)
        ERAISE(-EINVAL);

    if (!(ramfs = calloc(1, sizeof(ramfs_t))))
        ERAISE(-ENOMEM);

    ECHECK(_inode_new(NULL, "/", (S_IFDIR | MODE_RWX), &root_inode));

    ramfs->magic = RAMFS_MAGIC;
    ramfs->base = _base;
    ramfs->root = root_inode;
    libos_strlcpy(ramfs->target, "/", sizeof(ramfs->target));
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

int libos_ramfs_set_buf(
    libos_fs_t* fs,
    const char* pathname,
    const void* buf,
    size_t buf_size)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    inode_t* inode = NULL;
    int ret = 0;

    if (!_ramfs_valid(ramfs))
        ERAISE(-EINVAL);

    if (!pathname)
        ERAISE(-EINVAL);

    if (!buf && buf_size)
        ERAISE(-EINVAL);

    ECHECK(_path_to_inode(ramfs, pathname, true, NULL, &inode));

    if (inode->buf.data != inode->data)
        libos_buf_clear(&inode->buf);

    inode->data = buf;
    inode->buf.data = (void*)buf;
    inode->buf.size = buf_size;

done:

    return ret;
}
