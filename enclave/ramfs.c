#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <oel/fs.h>
#include <oel/ramfs.h>
#include <dirent.h>
#include "eraise.h"
#include "strings.h"
#include "bufu64.h"
#include "buf.h"

#define MODE_R   (S_IRUSR | S_IRGRP | S_IROTH)
#define MODE_W   (S_IWUSR | S_IWGRP | S_IWOTH)
#define MODE_X   (S_IXUSR | S_IXGRP | S_IXOTH)
#define MODE_RWX (MODE_R | MODE_W | MODE_X)

#define MAGIC 0x28F21778D1E711EA

/* Assume that d_ino is 8 bytes (big enough to hold a pointer) */
_Static_assert(sizeof(((struct dirent*)0)->d_ino) == 8, "d_ino");

/* Assume struct dirent is eight-byte aligned */
_Static_assert(sizeof(struct dirent) % 8 == 0, "dirent");

typedef struct ramfs
{
    uint64_t magic;
    oel_fs_t base;
    oel_inode_t* root;
}
ramfs_t;

struct oel_inode
{
    uint64_t magic;
    char name[PATH_MAX]; /* name of file or directory */
    uint32_t mode; /* Type and mode */
    size_t links; /* number of hard links */
    oel_buf_t data; /* file or directory data */
    oel_bufu64_t children; /* children (directories) */

    /* dynamic state data */
    size_t offset; /* the current file offset (files) */
    uint32_t open_access; /* (O_RDONLY | O_RDWR | O_WRONLY) */
};

static bool _valid_inode(const oel_inode_t* inode)
{
    return inode && inode->magic == MAGIC;
}

static bool _valid_ramfs(const ramfs_t* ramfs)
{
    return ramfs && ramfs->magic == MAGIC;
}

static int _new_inode(
    oel_inode_t* parent,
    const char* name,
    uint32_t mode,
    oel_inode_t** inode_out)
{
    int ret = 0;
    oel_inode_t* inode = NULL;

    if (!(inode = calloc(1, sizeof(oel_inode_t))))
        ERAISE(-ENOMEM);

    if (STRLCPY(inode->name, name) >= sizeof(inode->name))
        ERAISE(-ENAMETOOLONG);

    inode->magic = MAGIC;
    inode->mode = mode;
    inode->links = 1;

    /* The root directory is its own parent */
    if (!parent)
        parent = inode;

    /* If new inode is a directory, add the "." and ".." elements */
    if (S_ISDIR(mode))
    {
        /* Add the "." entry */
        {
            struct dirent ent =
            {
                .d_ino = (ino_t)inode,
                .d_off = (off_t)inode->data.size,
                .d_reclen = sizeof(struct dirent),
                .d_type = DT_DIR,
            };

            if (STRLCPY(ent.d_name, ".") >= sizeof(ent.d_name))
                ERAISE(-ENAMETOOLONG);

            if (oel_buf_append(&inode->data, &ent, sizeof(ent)) != 0)
                ERAISE(-ENOMEM);
        }

        /* Add the ".." entry */
        {
            struct dirent ent =
            {
                .d_ino = (ino_t)parent,
                .d_off = (off_t)inode->data.size,
                .d_reclen = sizeof(struct dirent),
                .d_type = DT_DIR,
            };

            if (STRLCPY(ent.d_name, "..") >= sizeof(ent.d_name))
                ERAISE(-ENAMETOOLONG);

            if (oel_buf_append(&inode->data, &ent, sizeof(ent)) != 0)
                ERAISE(-ENOMEM);
        }
    }

    /* Add this inode to the parent inode's directory table */
    if (parent != inode)
    {
        struct dirent ent =
        {
            .d_ino = (ino_t)parent,
            .d_off = (off_t)parent->data.size,
            .d_reclen = sizeof(struct dirent),
            .d_type = S_ISDIR(mode) ? DT_DIR : DT_REG,
        };

        if (STRLCPY(ent.d_name, name) >= sizeof(ent.d_name))
            ERAISE(-ENAMETOOLONG);

        if (oel_buf_append(&parent->data, &ent, sizeof(ent)) != 0)
            ERAISE(-ENOMEM);
    }

    *inode_out = inode;
    inode = NULL;

done:

    if (inode)
        free(inode);

    return ret;
}

static oel_inode_t* _find_child(const oel_inode_t* inode, const char* name)
{
    oel_inode_t** children = (oel_inode_t**)inode->children.data;

    for (size_t i = 0; i < inode->children.size; i++)
    {
        if (strcmp(children[i]->name, name) == 0)
            return children[i];
    }

    /* Not found */
    return NULL;
}

static int _add_child(oel_inode_t* parent, oel_inode_t* child)
{
    int ret = 0;

    if (oel_bufu64_append1(&parent->children, (uint64_t)child) != 0)
        ERAISE(-ENOMEM);

done:
    return ret;
}

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
        strlcpy(dirname, "/", PATH_MAX);
        strlcpy(basename, "/", PATH_MAX);
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
            strlcpy(dirname, "/", PATH_MAX);
        }
        else
        {
            size_t index = (size_t)(slash - path);
            strlcpy(dirname, path, PATH_MAX);

            if (index < PATH_MAX)
                dirname[index] = '\0';
            else
                dirname[PATH_MAX - 1] = '\0';
        }

        strlcpy(basename, slash + 1, PATH_MAX);
    }

done:
    return ret;
}

static int _path_to_inode(
    ramfs_t* ramfs,
    const char* path,
    oel_inode_t** inode_out)
{
    int ret = 0;
    const char* elements[PATH_MAX];
    const size_t MAX_ELEMENTS = sizeof(elements) / sizeof(elements[0]);
    size_t nelements = 0;
    char buf[PATH_MAX];

    if (inode_out)
        *inode_out = NULL;

    if (!path || !inode_out)
        ERAISE(-EINVAL);

    /* Fail if path does not begin with '/' */
    if (path[0] != '/')
        ERAISE(-EINVAL);

    /* Copy the path */
    if (STRLCPY(buf, path) >= sizeof(buf))
        ERAISE(-ENAMETOOLONG);

    /* Split the path into components */
    {
        char* p;
        char* save;

        for (p = strtok_r(buf, "/", &save); p; p = strtok_r(NULL, "/", &save))
        {
            assert(nelements < MAX_ELEMENTS);
            elements[nelements++] = p;
        }
    }

    /* First element should be "/" */
    assert(strcmp(elements[0], "/") == 0);

    /* search for the inode */
    {
        oel_inode_t* inode = NULL;

        if (nelements == 1)
        {
            inode = ramfs->root;
        }
        else
        {
            oel_inode_t* current = ramfs->root;

            for (size_t i = 1; i < nelements; i++)
            {
                if (!(current = _find_child(current, elements[i])))
                    ERAISE(-ENOENT);

                if (i == nelements)
                {
                    inode = current;
                    break;
                }
            }
        }

        if (!inode)
            ERAISE(-ENOENT);
    }

done:
    return ret;
}

/*
**==============================================================================
**
** interface:
**
**==============================================================================
*/

static int _fs_release(oel_fs_t* fs)
{
    (void)fs;
    return -EINVAL;
}

static int _fs_creat(oel_fs_t* fs, const char* pathname, mode_t mode)
{
    (void)fs;
    (void)pathname;
    (void)mode;
    return -EINVAL;
}

static int _fs_open(
    oel_fs_t* fs,
    const char* pathname,
    int flags,
    mode_t mode,
    oel_inode_t** inode_out)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    oel_inode_t* inode = NULL;
    int ret = 0;
    int errnum;
    bool is_new_inode = false;

    if (inode_out)
        *inode_out = NULL;

    if (!_valid_ramfs(ramfs) || !pathname || !inode)
        ERAISE(-EINVAL);

    errnum = _path_to_inode(ramfs, pathname, &inode);

    /* If the file already exists */
    if (errnum == 0)
    {
        if ((flags & O_CREAT) && (flags & O_EXCL))
            ERAISE(-EEXIST);

        if ((flags & O_DIRECTORY) && !S_ISDIR(inode->mode))
            ERAISE(-ENOTDIR);

        if ((flags & O_TRUNC))
            oel_buf_clear(&inode->data);

        if ((flags & O_APPEND))
            inode->offset = inode->data.size;
    }
    else if (errnum == -ENOENT)
    {
        char dirname[PATH_MAX];
        char basename[PATH_MAX];
        oel_inode_t* parent;

        is_new_inode = true;

        if (!(flags & O_CREAT))
            ERAISE(-ENOENT);

        /* Split the path into parent directory and file name */
        ECHECK(_split_path(pathname, dirname, basename));

        /* Get the inode of the parent directory. */
        ECHECK(_path_to_inode(ramfs, dirname, &parent));

        /* Create the new file inode */
        ECHECK(_new_inode(parent, basename, (S_IFREG | mode), &inode));

        /* Add new file inode to the parent */
        ECHECK(_add_child(parent, inode));
    }
    else
    {
        ERAISE(-errnum);
    }

    /* Save the file access flags */
    inode->open_access = (flags & (O_RDONLY | O_RDWR | O_WRONLY));

    *inode_out = inode;
    inode = NULL;

done:

    if (inode && is_new_inode)
        free(inode);

    return ret;
}

#pragma GCC diagnostic ignored "-Wunused-parameter"

static off_t _fs_lseek(oel_fs_t* fs, int fd, off_t offset, int whence)
{
    return -EINVAL;
}

static ssize_t _fs_read(
    oel_fs_t* fs,
    oel_inode_t* inode,
    void* buf,
    size_t count)
{
    ramfs_t* ramfs = (ramfs_t*)fs;
    int ret = 0;

    if (!_valid_ramfs(ramfs) || !_valid_inode(inode) || (!buf && count))
        ERAISE(-EINVAL);

    /* reading zero bytes */
    if (!count)
        return 0;

done:
    return ret;
}

static ssize_t _fs_write(oel_fs_t* fs, int fd, const void* buf, size_t count)
{
    return -EINVAL;
}

static ssize_t _fs_readv(
    oel_fs_t* fs,
    int fd,
    const struct iovec* iov,
    int iovcnt)
{
    return -EINVAL;
}

static ssize_t _fs_writev(
    oel_fs_t* fs,
    int fd,
    const struct iovec* iov,
    int iovcnt)
{
    return -EINVAL;
}

static int _fs_close(oel_fs_t* fs, int fd)
{
    return -EINVAL;
}

static int _fs_stat(oel_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    return -EINVAL;
}

static int _fs_fstat(oel_fs_t* fs, int fd, struct stat* statbuf)
{
    return -EINVAL;
}

static int _fs_link(oel_fs_t* fs, const char* oldpath, const char* newpath)
{
    return -EINVAL;
}

static int _fs_rename(oel_fs_t* fs, const char* oldpath, const char* newpath)
{
    return -EINVAL;
}

static int _fs_truncate(oel_fs_t* fs, const char* path, off_t length)
{
    return -EINVAL;
}

static int _fs_ftruncate(oel_fs_t* fs, int fd, off_t length)
{
    return -EINVAL;
}

static int _fs_mkdir(oel_fs_t* fs, const char* pathname, mode_t mode)
{
    return -EINVAL;
}

static int _fs_rmdir(oel_fs_t* fs, const char* pathname)
{
    return -EINVAL;
}

static int _fs_opendir(oel_fs_t* fs, const char* name, DIR** dirp)
{
    return -EINVAL;
}

static int _fs_readdir(oel_fs_t* fs, DIR* dirp, struct dirent** direntp)
{
    return -EINVAL;
}

static int _fs_closedir(oel_fs_t* fs, DIR* dirp)
{
    return -EINVAL;
}

int oel_init_ramfs(oel_fs_t** fs_out)
{
    int ret = 0;
    ramfs_t* ramfs = NULL;
    static oel_fs_t _base =
    {
        _fs_release,
        _fs_creat,
        _fs_open,
        _fs_lseek,
        _fs_read,
        _fs_write,
        _fs_readv,
        _fs_writev,
        _fs_close,
        _fs_stat,
        _fs_fstat,
        _fs_link,
        _fs_rename,
        _fs_truncate,
        _fs_ftruncate,
        _fs_mkdir,
        _fs_rmdir,
        _fs_opendir,
        _fs_readdir,
        _fs_closedir,
    };
    oel_inode_t* root_inode = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (!fs_out)
        ERAISE(-EINVAL);

    if (!(ramfs = calloc(1, sizeof(ramfs_t))))
        ERAISE(-ENOMEM);

    ECHECK(_new_inode(NULL, "/", (S_IFDIR | MODE_RWX), &root_inode));

    ramfs->magic = MAGIC;
    ramfs->base = _base;
    ramfs->root = root_inode;
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
