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

#include <myst/assume.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/fs.h>
#include <myst/hostfs.h>
#include <myst/iov.h>
#include <myst/realpath.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/uid_gid.h>

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

static int _get_host_uid_gid(uid_t* host_uid, gid_t* host_gid)
{
    int ret = 0;

    ECHECK(myst_enc_uid_to_host(myst_syscall_geteuid(), host_uid));
    ECHECK(myst_enc_gid_to_host(myst_syscall_getegid(), host_gid));

done:
    return ret;
}

static bool _hostfs_valid(const hostfs_t* hostfs)
{
    return hostfs && hostfs->magic == HOSTFS_MAGIC;
}

int myst_hostfs_suffix_to_host_abspath(
    void* fs,
    char* buf,
    size_t size,
    const char* path)
{
    const hostfs_t* hostfs = (hostfs_t*)fs;
    if (!_hostfs_valid(hostfs))
        return -EINVAL;

    if (myst_strlcpy(buf, hostfs->source, size) >= size)
        return -ENAMETOOLONG;

    if (path[0] != '/')
    {
        if (myst_strlcat(buf, "/", size) >= size)
            return -ENAMETOOLONG;
    }

    if (myst_strlcat(buf, path, size) >= size)
        return -ENAMETOOLONG;

    return 0;
}

static int _to_local_path(
    hostfs_t* hostfs,
    char* buf,
    size_t size,
    const char* path)
{
    const size_t len = strlen(hostfs->source);

    if (strncmp(hostfs->source, path, len) == 0)
        path += len;

    myst_strlcpy(buf, path, size);

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
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    myst_file_t* file = NULL;
    char* path = NULL;
    long tret;
    uid_t host_uid;
    gid_t host_gid;

    myst_assume(hostfs->magic == HOSTFS_MAGIC);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    if (!_hostfs_valid(hostfs) || !pathname || !file_out)
        ERAISE(-EINVAL);

    if (!(file = calloc(1, sizeof(myst_file_t))))
        ERAISE(-ENOMEM);

    ECHECK(myst_realpath(pathname, (myst_path_t*)file->realpath));

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    long params[6] = {(long)path, flags, mode, host_uid, host_gid};
    ECHECK((tret = myst_tcall(SYS_open, params)));

    if (tret > MYST_FDTABLE_SIZE)
        ERAISE(-EINVAL);

    file->magic = FILE_MAGIC;
    file->fd = (int)tret;

    *file_out = file;
    file = NULL;
    /* hostfs does not delegate the open operation */
    *fs_out = fs;

done:

    if (file)
        free(file);

    if (path)
        free(path);

    return ret;
}

static int _fs_creat(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file)
{
    return _fs_open(
        fs, pathname, O_CREAT | O_WRONLY | O_TRUNC, mode, fs_out, file);
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

    if (!_hostfs_valid(hostfs) || !file)
        ERAISE(-EINVAL);

    ret = myst_fdops_readv(&fs->fdops, file, iov, iovcnt);
    ECHECK(ret);

done:
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

    if (!_hostfs_valid(hostfs) || !file)
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&fs->fdops, file, iov, iovcnt);
    ECHECK(ret);

done:
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
    char* path = NULL;

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    long params[6] = {(long)path, mode};
    ECHECK((tret = myst_tcall(SYS_access, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (path)
        free(path);

    return ret;
}

/* Map uid and gid fields of statbuf to in-enclave values */
static int _map_stat_to_enc_ids(struct stat* statbuf)
{
    int ret = 0;

    ECHECK(myst_host_uid_to_enc(statbuf->st_uid, &statbuf->st_uid));
    ECHECK(myst_host_gid_to_enc(statbuf->st_gid, &statbuf->st_gid));

done:
    return ret;
}

static int _fs_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char* path = NULL;
    uid_t host_uid;
    gid_t host_gid;

    myst_assume(hostfs->magic == HOSTFS_MAGIC);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    // ATTN: special handling needed for symbolic links. Check to see if it
    // is a link, and if so, use readlink to get the name of the file.

    if (!_hostfs_valid(hostfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    long params[6] = {
        (long)path, (long)statbuf, (long)host_uid, (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_stat, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

    ECHECK(_map_stat_to_enc_ids(statbuf));

done:

    if (path)
        free(path);

    return ret;
}

static int _fs_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char* path = NULL;
    uid_t host_uid;
    gid_t host_gid;

    if (!_hostfs_valid(hostfs) || !pathname || !statbuf)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    long params[6] = {
        (long)path, (long)statbuf, (long)host_uid, (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_lstat, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

    ECHECK(_map_stat_to_enc_ids(statbuf));

done:

    if (path)
        free(path);

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

    ECHECK(_map_stat_to_enc_ids(statbuf));

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
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    struct locals
    {
        char opath[PATH_MAX];
        char npath[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!_hostfs_valid(hostfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_hostfs_suffix_to_host_abspath(
        hostfs, locals->opath, sizeof(locals->opath), oldpath));
    ECHECK(myst_hostfs_suffix_to_host_abspath(
        hostfs, locals->npath, sizeof(locals->npath), newpath));

    long params[6] = {(long)AT_FDCWD,
                      (long)locals->opath,
                      (long)AT_FDCWD,
                      (long)locals->npath,
                      (long)flags};
    ECHECK((tret = myst_tcall(SYS_linkat, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_unlink(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char* path = NULL;

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    long params[6] = {(long)path};
    ECHECK((tret = myst_tcall(SYS_unlink, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (path)
        free(path);

    return ret;
}

static int _fs_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    struct locals
    {
        char opath[PATH_MAX];
        char npath[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!_hostfs_valid(hostfs) || !oldpath || !newpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_hostfs_suffix_to_host_abspath(
        hostfs, locals->opath, sizeof(locals->opath), oldpath));
    ECHECK(myst_hostfs_suffix_to_host_abspath(
        hostfs, locals->npath, sizeof(locals->npath), newpath));

    long params[6] = {(long)locals->opath, (long)locals->npath};
    ECHECK((tret = myst_tcall(SYS_rename, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_truncate(myst_fs_t* fs, const char* path, off_t length)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char* hpath = NULL;

    if (!_hostfs_valid(hostfs) || !path || length < 0)
        ERAISE(-EINVAL);

    if (!(hpath = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(myst_hostfs_suffix_to_host_abspath(hostfs, hpath, PATH_MAX, path));

    long params[6] = {(long)hpath, length};
    ECHECK((tret = myst_tcall(SYS_truncate, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (hpath)
        free(hpath);

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
    char* path = NULL;
    uid_t host_uid;
    gid_t host_gid;

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    long params[6] = {(long)path, (long)mode, (long)host_uid, (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_mkdir, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (path)
        free(path);

    return ret;
}

static int _fs_rmdir(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    char* path = NULL;
    uid_t host_uid;
    gid_t host_gid;

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    long params[6] = {(long)path, (long)host_uid, (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_rmdir, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (path)
        free(path);

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
    struct locals
    {
        char path[PATH_MAX];
        char target[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!_hostfs_valid(hostfs) || !pathname || !buf || !bufsiz)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_hostfs_suffix_to_host_abspath(
        hostfs, locals->path, PATH_MAX, pathname));

    long params[6] = {(long)locals->path, (long)locals->target, PATH_MAX};
    ECHECK((tret = myst_tcall(SYS_readlink, params)));

    if (tret < PATH_MAX)
        locals->target[tret] = '\0';
    else
        locals->target[PATH_MAX - 1] = '\0';

    ECHECK(_to_local_path(hostfs, buf, bufsiz, locals->target));
    tret = strlen(buf);

    ret = tret;

done:

    if (locals)
        free(locals);

    return ret;
}

static int _fs_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    struct locals
    {
        char host_linkpath[PATH_MAX];
        char host_target[PATH_MAX];
    };
    struct locals* locals = NULL;
    uid_t host_uid;
    gid_t host_gid;

    if (!_hostfs_valid(hostfs) || !target || !linkpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Note: store target as-is (it may refer to a different file system) */

    ECHECK(myst_hostfs_suffix_to_host_abspath(
        hostfs, locals->host_linkpath, PATH_MAX, linkpath));

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    if (target[0] == '/')
        ECHECK(myst_hostfs_suffix_to_host_abspath(
            hostfs, locals->host_target, PATH_MAX, target));
    else
        myst_strlcpy(locals->host_target, target, PATH_MAX);

    long params[6] = {(long)locals->host_target,
                      (long)locals->host_linkpath,
                      (long)host_uid,
                      (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_symlink, params)));

    ret = tret;

done:

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
        if (myst_strlcpy(buf, hostfs->target, size) >= size)
            ERAISE(-ENAMETOOLONG);

        if (myst_strlcat(buf, file->realpath, size) >= size)
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

    if (request == FIOCLEX || request == FIONCLEX || request == FIONBIO)
    {
        long tret, params[6] = {file->fd, request, arg};
        ECHECK((tret = myst_tcall(SYS_ioctl, params)));
        goto done;
    }

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

static int _fs_statfs(myst_fs_t* fs, const char* pathname, struct statfs* buf)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    char* path = NULL;
    long tret;

    if (!_hostfs_valid(hostfs) || !pathname || !buf)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    long params[6] = {(long)path, (long)buf};
    ECHECK((tret = myst_tcall(SYS_statfs, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:

    if (path)
        free(path);

    return ret;
}

static int _fs_fstatfs(myst_fs_t* fs, myst_file_t* file, struct statfs* buf)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file) || !buf)
        ERAISE(-EINVAL);

    long params[6] = {file->fd, (long)buf};
    ECHECK((tret = myst_tcall(SYS_fstatfs, params)));

    if (tret != 0)
        ERAISE(-EINVAL);

    ret = tret;

done:
    return ret;
}

static int _fs_futimens(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct timespec times[2])
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    uid_t host_uid;
    gid_t host_gid;

    myst_assume(hostfs->magic == HOSTFS_MAGIC);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    long params[6] = {
        (long)file->fd, (long)NULL, (long)times, 0, host_uid, host_gid};
    ECHECK((tret = myst_tcall(SYS_utimensat, params)));
    ret = tret;

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
    hostfs_t* hostfs = (hostfs_t*)fs;
    char* path = NULL;
    long tret;
    uid_t host_uid;
    gid_t host_gid;
    uid_t host_owner = -1u;
    gid_t host_group = -1u;

    myst_assume(hostfs->magic == HOSTFS_MAGIC);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    if (owner != -1)
        ECHECK(myst_enc_uid_to_host(owner, &host_owner));

    if (group != -1)
        ECHECK(myst_enc_gid_to_host(group, &host_group));

    long params[6] = {(long)path,
                      (long)host_owner,
                      (long)host_group,
                      (long)host_uid,
                      (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_chown, params)));

done:

    if (path)
        free(path);

    return ret;
}

static int _fs_fchown(
    myst_fs_t* fs,
    myst_file_t* file,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    uid_t host_uid;
    gid_t host_gid;
    uid_t host_owner = -1u;
    gid_t host_group = -1u;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    if (owner != -1)
        ECHECK(myst_enc_uid_to_host(owner, &host_owner));

    if (group != -1)
        ECHECK(myst_enc_gid_to_host(group, &host_group));

    long params[6] = {file->fd,
                      (long)host_owner,
                      (long)host_group,
                      (long)host_uid,
                      (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_fchown, params)));

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
    hostfs_t* hostfs = (hostfs_t*)fs;
    char* path = NULL;
    long tret;
    uid_t host_uid;
    gid_t host_gid;
    uid_t host_owner = -1u;
    gid_t host_group = -1u;

    myst_assume(hostfs->magic == HOSTFS_MAGIC);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    if (owner != -1)
        ECHECK(myst_enc_uid_to_host(owner, &host_owner));

    if (group != -1)
        ECHECK(myst_enc_gid_to_host(group, &host_group));

    long params[6] = {(long)path,
                      (long)host_owner,
                      (long)host_group,
                      (long)host_uid,
                      (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_lchown, params)));

done:

    if (path)
        free(path);

    return ret;
}

static int _fs_chmod(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    char* path = NULL;
    long tret;
    uid_t host_uid;
    gid_t host_gid;

    myst_assume(hostfs->magic == HOSTFS_MAGIC);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    if (!_hostfs_valid(hostfs) || !pathname)
        ERAISE(-EINVAL);

    if (!(path = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(
        myst_hostfs_suffix_to_host_abspath(hostfs, path, PATH_MAX, pathname));

    long params[6] = {(long)path, (long)mode, (long)host_uid, (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_chmod, params)));

done:

    if (path)
        free(path);

    return ret;
}

static int _fs_fchmod(myst_fs_t* fs, myst_file_t* file, mode_t mode)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;
    uid_t host_uid;
    gid_t host_gid;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ECHECK(_get_host_uid_gid(&host_uid, &host_gid));

    long params[6] = {file->fd, (long)mode, (long)host_uid, (long)host_gid};
    ECHECK((tret = myst_tcall(SYS_fchmod, params)));

done:
    return ret;
}

static int _fs_fdatasync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    long params[6] = {file->fd};
    ECHECK((tret = myst_tcall(SYS_fdatasync, params)));
    ret = tret;

done:
    return ret;
}

static int _fs_fsync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;
    long tret;

    if (!_hostfs_valid(hostfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    long params[6] = {file->fd};
    ECHECK((tret = myst_tcall(SYS_fsync, params)));
    ret = tret;

done:
    return ret;
}

static int _fs_release_tree(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    hostfs_t* hostfs = (hostfs_t*)fs;

    if (!_hostfs_valid(hostfs) || !pathname)
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
        .fs_statfs = _fs_statfs,
        .fs_fstatfs = _fs_fstatfs,
        .fs_futimens = _fs_futimens,
        .fs_chown = _fs_chown,
        .fs_fchown = _fs_fchown,
        .fs_lchown = _fs_lchown,
        .fs_chmod = _fs_chmod,
        .fs_fchmod = _fs_fchmod,
        .fs_fdatasync = _fs_fdatasync,
        .fs_fsync = _fs_fsync,
        .fs_release_tree = _fs_release_tree,
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
    myst_strlcpy(hostfs->target, "/", sizeof(hostfs->target));

    *fs_out = &hostfs->base;
    hostfs = NULL;

done:

    if (hostfs)
        free(hostfs);

    return ret;
}

bool myst_is_hostfs(const myst_fs_t* fs)
{
    return _hostfs_valid((hostfs_t*)fs);
}

#endif /* MYST_ENABLE_HOSTFS */
