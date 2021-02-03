// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifdef MYST_ENABLE_HOSTFS

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/fs.h>
#include <myst/iov.h>
#include <myst/realpath.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>

/*
**==============================================================================
**
** hostfs_t:
**
**==============================================================================
*/

#define HOSTFS_MAGIC 0x72bd543fe97e4fec

typedef struct inode inode_t;

typedef struct hostfs
{
    myst_fs_t base;
    uint64_t magic;
    char source[PATH_MAX]; /* source argument to myst_mount() */
    char target[PATH_MAX]; /* target argument to myst_mount() */
} hostfs_t;

static bool _hostfs_valid(const hostfs_t* hostfs)
{
    return hostfs && hostfs->magic == HOSTFS_MAGIC;
}

static int _fixup_path(
    hostfs_t* hostfs,
    char* buf,
    size_t size,
    const char* path)
{
    if (myst_strlcpy(buf, hostfs->source, size) >= size)
        return -ENAMETOOLONG;

    if (myst_strlcat(buf, "/", size) >= size)
        return -ENAMETOOLONG;

    if (myst_strlcat(buf, path, size) >= size)
        return -ENAMETOOLONG;

    return 0;
}

/*
**==============================================================================
**
** myst_file_t
**
**==============================================================================
*/

#define FILE_MAGIC 0xb02950b846ff4d31

struct myst_file
{
    uint64_t magic;
    char realpath[PATH_MAX];
    int fd;
};

static bool _file_valid(const myst_file_t* file)
{
    return file && file->magic == FILE_MAGIC;
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
    hostfs_t* hostfs = (hostfs_t*)fs;

    if (!_hostfs_valid(hostfs))
        ERAISE(-EINVAL);

    memset(hostfs, 0xdd, sizeof(hostfs_t));
    free(hostfs);

done:
    return ret;
}

static int _fs_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;

    if (!_hostfs_valid(hostfs) || !target)
        ERAISE(-EINVAL);

    if (myst_strlcpy(hostfs->target, target, PATH_MAX) >= PATH_MAX)
        ERAISE(-ENAMETOOLONG);

    if (myst_strlcpy(hostfs->source, source, PATH_MAX) >= PATH_MAX)
        ERAISE(-ENAMETOOLONG);

done:
    return ret;
}

static int _fs_open(
    myst_fs_t* fs,
    const char* pathname,
    int flags,
    mode_t mode,
    myst_file_t** file_out)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    myst_file_t* file = NULL;
    char path[PATH_MAX];
    long tret;

    if (!_hostfs_valid(hostfs) || !pathname || !file_out)
        ERAISE(-EINVAL);

    if (!(file = calloc(1, sizeof(myst_file_t))))
        ERAISE(-ENOMEM);

    ECHECK(myst_realpath(pathname, (myst_path_t*)file->realpath));

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path, flags, mode};
    ECHECK((tret = myst_tcall(SYS_open, params)));

    if (tret > MYST_FDTABLE_SIZE)
        ERAISE(-EINVAL);

    file->magic = FILE_MAGIC;
    file->fd = (int)tret;

    *file_out = file;
    file = NULL;

done:

    if (file)
        free(file);

    return ret;
}

static int _fs_creat(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_file_t** file)
{
    return _fs_open(fs, pathname, O_CREAT | O_WRONLY | O_TRUNC, mode, file);
}

static off_t _fs_lseek(
    myst_fs_t* fs,
    myst_file_t* file,
    off_t offset,
    int whence)
{
    hostfs_t* hostfs = (hostfs_t*)fs;
    off_t ret = 0;
    off_t tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    long params[6] = {file->fd, offset, whence};
    ECHECK((tret = myst_tcall(SYS_lseek, params)));

    ret = tret;

done:
    return ret;
}

static ssize_t _fs_read(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count)
{
    hostfs_t* hostfs = (hostfs_t*)fs;
    ssize_t ret = 0;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    long params[6] = {file->fd, (long)buf, count};
    ECHECK((tret = myst_tcall(SYS_read, params)));

    ret = tret;

done:
    return ret;
}

static ssize_t _fs_write(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count)
{
    hostfs_t* hostfs = (hostfs_t*)fs;
    ssize_t ret = 0;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    long params[6] = {file->fd, (long)buf, count};
    ECHECK((tret = myst_tcall(SYS_write, params)));

    ret = tret;

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
    hostfs_t* hostfs = (hostfs_t*)fs;
    ssize_t ret = 0;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    long params[6] = {file->fd, (long)buf, count, offset};
    ECHECK((tret = myst_tcall(SYS_pread64, params)));

    ret = tret;

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
    hostfs_t* hostfs = (hostfs_t*)fs;
    ssize_t ret = 0;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    long params[6] = {file->fd, (long)buf, count, offset};
    ECHECK((tret = myst_tcall(SYS_pwrite64, params)));

    ret = tret;

done:
    return ret;
}

static ssize_t _fs_readv(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    hostfs_t* hostfs = (hostfs_t*)fs;
    ssize_t ret = 0;
    void* buf = NULL;
    ssize_t len;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ECHECK(len = myst_iov_len(iov, iovcnt));

    if (len == 0)
        goto done;

    if (!(buf = calloc(len, 1)))
        ERAISE(-ENOMEM);

    long params[6] = {file->fd, (long)buf, len};
    ECHECK((tret = myst_tcall(SYS_read, params)));

    ECHECK(myst_iov_scatter(iov, iovcnt, buf, len));

    ret = tret;

done:

    if (buf)
        free(buf);

    return ret;
}

static ssize_t _fs_writev(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    hostfs_t* hostfs = (hostfs_t*)fs;
    ssize_t ret = 0;
    void* buf = NULL;
    ssize_t len;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ECHECK(len = myst_iov_gather(iov, iovcnt, &buf));

    if (len == 0)
        goto done;

    long params[6] = {file->fd, (long)buf, len};
    ECHECK((tret = myst_tcall(SYS_write, params)));

    ret = tret;

done:

    if (buf)
        free(buf);

    return ret;
}

static int _fs_close(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    long params[6] = {file->fd};
    ECHECK((tret = myst_tcall(SYS_close, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    memset(file, 0xdd, sizeof(myst_file_t));
    free(file);

    ret = tret;

done:
    return ret;
}

static int _fs_access(myst_fs_t* fs, const char* pathname, int mode)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path, mode};
    ECHECK((tret = myst_tcall(SYS_access, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    return ret;
}

static int _fs_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    // ATTN: special handling needed for symbolic links. Check to see if it
    // is a link, and if so, use readlink to get the name of the file.

    if (!_hostfs_valid(hostfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path, (long)statbuf};
    ECHECK((tret = myst_tcall(SYS_stat, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path, (long)statbuf};
    ECHECK((tret = myst_tcall(SYS_lstat, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file) || !statbuf)
        ERAISE(-EINVAL);

    long params[6] = {file->fd, (long)statbuf};
    ECHECK((tret = myst_tcall(SYS_fstat, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_link(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char opath[PATH_MAX];
    char npath[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, opath, sizeof(opath), oldpath));
    ECHECK(_fixup_path(hostfs, npath, sizeof(npath), newpath));

    long params[6] = {(long)opath, (long)npath};
    ECHECK((tret = myst_tcall(SYS_link, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_unlink(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path};
    ECHECK((tret = myst_tcall(SYS_unlink, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char opath[PATH_MAX];
    char npath[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, opath, sizeof(opath), oldpath));
    ECHECK(_fixup_path(hostfs, npath, sizeof(npath), newpath));

    long params[6] = {(long)opath, (long)npath};
    ECHECK((tret = myst_tcall(SYS_rename, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_truncate(myst_fs_t* fs, const char* path, off_t length)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char hpath[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !path || length < 0)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, hpath, sizeof(hpath), path));

    long params[6] = {(long)hpath, length};
    ECHECK((tret = myst_tcall(SYS_truncate, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file) || length < 0)
        ERAISE(-EINVAL);

    long params[6] = {file->fd, length};
    ECHECK((tret = myst_tcall(SYS_ftruncate, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_mkdir(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path, mode};
    ECHECK((tret = myst_tcall(SYS_mkdir, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_rmdir(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path};
    ECHECK((tret = myst_tcall(SYS_rmdir, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_getdents64(
    myst_fs_t* fs,
    myst_file_t* file,
    struct dirent* dirp,
    size_t count)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file) || !dirp)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    /* ATTN: check sizes of respective dirent structures */

    long params[6] = {file->fd, (long)dirp, count};
    ECHECK((tret = myst_tcall(SYS_getdents64, params)));

    ret = tret;

done:
    return ret;
}

static ssize_t _fs_readlink(
    myst_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    ssize_t ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !pathname || !buf || !bufsiz)
        ERAISE(-EINVAL);

    ECHECK(_fixup_path(hostfs, path, sizeof(path), pathname));

    long params[6] = {(long)path, (long)buf, bufsiz};
    ECHECK((tret = myst_tcall(SYS_readlink, params)));

    ret = tret;

done:

    return ret;
}

static int _fs_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char path[PATH_MAX];

    if (!_hostfs_valid(hostfs) || !target || !linkpath)
        ERAISE(-EINVAL);

    /* Note: store target as-is (it may refer to a different file system) */

    ECHECK(_fixup_path(hostfs, path, sizeof(path), linkpath));

    long params[6] = {(long)target, (long)path};
    ECHECK((tret = myst_tcall(SYS_symlink, params)));

    ret = tret;

done:

    return ret;
}

static int _fs_realpath(
    myst_fs_t* fs,
    myst_file_t* file,
    char* buf,
    size_t size)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;

    if (!_hostfs_valid(hostfs) || !_file_valid(file) || !buf || !size)
        ERAISE(-EINVAL);

    if (strcmp(hostfs->target, "/") == 0)
    {
        if (myst_strlcpy(buf, file->realpath, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        int n = snprintf(buf, size, "%s%s", hostfs->target, file->realpath);

        if (n < 0 || n >= (int)size)
            ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

static int _fs_fcntl(myst_fs_t* fs, myst_file_t* file, int cmd, long arg)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    long params[6] = {file->fd, cmd, arg};
    ECHECK((tret = myst_tcall(SYS_fcntl, params)));

    ret = tret;

done:
    return ret;
}

static int _fs_ioctl(
    myst_fs_t* fs,
    myst_file_t* file,
    unsigned long request,
    long arg)
{
    hostfs_t* hostfs = (hostfs_t*)fs;
    int ret = 0;

    (void)arg;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EBADF);

    if (request == TIOCGWINSZ)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _fs_dup(
    myst_fs_t* fs,
    const myst_file_t* file,
    myst_file_t** file_out)
{
    hostfs_t* hostfs = (hostfs_t*)fs;
    int ret = 0;
    myst_file_t* new_file = NULL;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file) || !file_out)
        ERAISE(-EINVAL);

    if (!(new_file = calloc(1, sizeof(myst_file_t))))
        ERAISE(-ENOMEM);

    *new_file = *file;

    long params[6] = {file->fd};
    ECHECK((tret = myst_tcall(SYS_dup, params)));

    new_file->fd = tret;
    ret = tret;

    *file_out = new_file;
    new_file = NULL;

done:

    if (new_file)
    {
        memset(new_file, 0xdd, sizeof(myst_file_t));
        free(new_file);
    }

    return ret;
}

static int _fs_target_fd(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ret = file->fd;

done:
    return ret;
}

static int _fs_get_events(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

int myst_init_hostfs(myst_fs_t** fs_out)
{
    int ret = 0;
    hostfs_t* hostfs = NULL;
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
    };
    // clang-format on

    if (fs_out)
        *fs_out = NULL;

    if (!fs_out)
        ERAISE(-EINVAL);

    if (!(hostfs = calloc(1, sizeof(hostfs_t))))
        ERAISE(-ENOMEM);

    hostfs->magic = HOSTFS_MAGIC;
    hostfs->base = _base;
    strcpy(hostfs->target, "/");

    *fs_out = &hostfs->base;
    hostfs = NULL;

done:

    if (hostfs)
        free(hostfs);

    return ret;
}

#endif /* MYST_ENABLE_HOSTFS */
