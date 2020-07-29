#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <oel/fs.h>
#include <oel/ramfs.h>
#include "eraise.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

#define MODE_RD  (S_IRUSR | S_IRGRP | S_IROTH)
#define MODE_WR (S_IWUSR | S_IWGRP | S_IWOTH)
#define MODE_EX  (S_IXUSR | S_IXGRP | S_IXOTH)

typedef struct ramfs
{
    oel_fs_t base;
    bool rdonly;
    oel_inode_t* root;
}
ramfs_t;

struct oel_inode
{
    char name[PATH_MAX]; /* name of file or directory */
    uint32_t mode; /* MODE_RD or (MODE_RD|MODE_WR) */
    uint8_t type; /* DT_DIR or DT_REG */
    size_t links; /* number of hard links */
    uint8_t* data; /* blocks (files) */
    size_t size; /* the size (files) or 0 (directories) */
    size_t offset; /* the current file offset (files) */
    oel_inode_t* next; /* next sibling file or null for directories */
    oel_inode_t* child; /* child file */
};

static int _fs_release(oel_fs_t* fs)
{
    return -EINVAL;
}

static int _fs_creat(oel_fs_t* fs, const char* pathname, mode_t mode)
{
    return -EINVAL;
}

static int _fs_open(
    oel_fs_t* fs,
    const char* pathname,
    int flags, mode_t mode,
    oel_inode_t** inode)
{
    return -EINVAL;
}

static off_t _fs_lseek(oel_fs_t* fs, int fd, off_t offset, int whence)
{
    return -EINVAL;
}

static ssize_t _fs_read(oel_fs_t* fs, int fd, void* buf, size_t count)
{
    return -EINVAL;
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

static int _new_inode(
    const char* name,
    bool dir,
    bool rdonly,
    oel_inode_t** inode_out)
{
    int ret = 0;
    oel_inode_t* inode = NULL;

    if (!(inode = calloc(1, sizeof(oel_inode_t))))
        ERAISE(-ENOMEM);

    if (strlcpy(inode->name, name, sizeof(inode->name)) >= sizeof(inode->name))
        ERAISE(-ENAMETOOLONG);

    inode->mode = rdonly ? MODE_RD : (MODE_RD|MODE_WR);
    inode->type = dir ? DT_DIR : DT_REG;
    inode->links = 1;

    *inode_out = inode;
    inode = NULL;

done:

    if (inode)
        free(inode);

    return ret;
}

int oel_init_ramfs(bool rdonly, oel_fs_t** fs_out)
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

    if (!fs_out)
        ERAISE(-EINVAL);

    if (!(ramfs = calloc(1, sizeof(ramfs_t))))
        ERAISE(-ENOMEM);

    ECHECK(_new_inode("/", DT_DIR, rdonly, &root_inode));

    ramfs->base = _base;
    ramfs->rdonly = rdonly;
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
