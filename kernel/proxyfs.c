// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/listener.h>
#include <myst/lockfs.h>
#include <myst/mutex.h>
#include <myst/panic.h>
#include <myst/proxyfs.h>
#include <myst/strings.h>

#define PROXYFS_MAGIC 0xc104776388f94032

#define FILE_MAGIC 0x3e0ef5bd564245f9

/* ATTN: cache proxy devices */

typedef struct proxyfs
{
    myst_fs_t base;
    uint64_t magic;
    uint64_t fs_cookie;
} proxyfs_t;

static bool _proxyfs_valid(const proxyfs_t* proxyfs)
{
    return proxyfs && proxyfs->magic == PROXYFS_MAGIC;
}

struct myst_file
{
    uint64_t magic;
    uint64_t file_cookie;
    _Atomic(size_t) use_count;
};

static bool _file_valid(const myst_file_t* file)
{
    return file && file->magic == FILE_MAGIC;
}

static ssize_t _new_request(
    size_t struct_size,
    size_t extra_bytes,
    void** req_out)
{
    ssize_t ret = 0;
    size_t req_size = struct_size + extra_bytes;
    uint8_t* req;

    if (!(req = calloc(1, req_size)))
        ERAISE(-ENOMEM);

    *req_out = req;
    ret = req_size;

done:
    return ret;
}

static uint64_t _fs_id(myst_fs_t* fs)
{
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        return 0;

    return proxyfs->fs_cookie;
}

static int _fs_release(myst_fs_t* fs)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    free(proxyfs);

done:
    return ret;
}

static int _twopathop(
    myst_fs_t* fs,
    const char* path1,
    const char* path2,
    myst_message_type_t mt)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;
    myst_pathop_request_t* req = NULL;
    myst_pathop_response_t* rsp = NULL;
    size_t req_size;
    size_t rsp_size;

    if (!_proxyfs_valid(proxyfs) || !path1 || !path2)
        ERAISE(-EINVAL);

    /* create and initialize the req structure */
    {
        const size_t path1_size = strlen(path1) + 1;
        const size_t path2_size = strlen(path2) + 1;
        const size_t extra = path1_size + path2_size;

        ECHECK((req_size = _new_request(sizeof(*req), extra, (void**)&req)));
        req->fs_cookie = proxyfs->fs_cookie;
        memcpy(req->pathname, path1, path1_size);
        memcpy(&req->pathname[path1_size], path2, path2_size);
    }

    /* call into the listener */
    ECHECK(myst_call_listener_helper(
        mt, req, req_size, sizeof(*rsp), (void**)&rsp, &rsp_size));

    ret = rsp->retval;

done:
    return ret;
}

static int _pathop(
    myst_fs_t* fs,
    const char* pathname,
    myst_pathop_args_t* args,
    void* buf,
    size_t bufsize,
    myst_message_type_t mt)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;
    myst_pathop_request_t* req = NULL;
    myst_pathop_response_t* rsp = NULL;
    size_t req_size;
    size_t rsp_size;

    if (!_proxyfs_valid(proxyfs) || !pathname)
        ERAISE(-EINVAL);

    /* create and initialize the req structure */
    {
        size_t extra = strlen(pathname) + 1;

        ECHECK((req_size = _new_request(sizeof(*req), extra, (void**)&req)));
        req->fs_cookie = proxyfs->fs_cookie;
        req->args = *args;
        req->bufsize = bufsize;
        memcpy(req->pathname, pathname, extra);
    }

    /* call into the listener */
    ECHECK(myst_call_listener_helper(
        mt, req, req_size, sizeof(*rsp), (void**)&rsp, &rsp_size));

    if (buf && bufsize)
    {
        size_t rem = rsp_size - sizeof(*rsp);

        if (rem)
            memcpy(buf, rsp->buf, rem);
    }

    ret = rsp->retval;

done:

    if (req)
        free(req);

    if (rsp)
        free(rsp);

    return ret;
}

static off_t _fileop(
    myst_fs_t* fs,
    myst_file_t* file,
    myst_fileop_args_t* args,
    const void* inbuf,
    size_t inbufsize,
    void* outbuf,
    size_t outbufsize,
    myst_message_type_t mt)
{
    ssize_t ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;
    myst_fileop_request_t* req = NULL;
    size_t req_size = sizeof(*req) + inbufsize;
    myst_fileop_response_t* rsp = NULL;
    size_t rsp_size;

    if (!_proxyfs_valid(proxyfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (!(req = calloc(1, req_size)))
        ERAISE(-ENOMEM);

    /* initialize the req structure */
    req->fs_cookie = proxyfs->fs_cookie;
    req->file_cookie = file->file_cookie;
    req->args = *args;
    req->inbufsize = inbufsize;
    req->outbufsize = outbufsize;

    if (inbuf && inbufsize)
        memcpy(req->buf, inbuf, inbufsize);

    /* call into the listener */
    ECHECK(myst_call_listener_helper(
        mt, req, req_size, sizeof(*rsp), (void**)&rsp, &rsp_size));

    if (outbuf && outbufsize)
    {
        size_t rem = rsp_size - sizeof(*rsp);

        if (rem)
            memcpy(outbuf, rsp->buf, rem);
    }

    ECHECK(rsp->retval);

    ret = rsp->retval;

done:

    if (req)
        free(req);

    if (rsp)
        free(rsp);

    return ret;
}

/*
**==============================================================================
**
** Public interface
**
**==============================================================================
*/

static int _fs_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    (void)source;
    (void)target;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    /* ATTN: how can this be implemented in a forked child? */
    ERAISE(-ENOTSUP);

done:
    return ret;
}

static int _fs_creat(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;
    const int flags = O_CREAT | O_WRONLY | O_TRUNC;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    ERAISE((*fs->fs_open)(fs, pathname, flags, mode, fs_out, file_out));

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;
    myst_open_request_t* req = NULL;
    myst_open_response_t* rsp = NULL;
    size_t req_size;
    size_t rsp_size;
    myst_fs_t* new_fs = NULL;
    myst_file_t* new_file = NULL;

    if (*fs_out)
        *fs_out = NULL;

    if (*file_out)
        *file_out = NULL;

    if (!_proxyfs_valid(proxyfs) || !pathname || !fs_out || !file_out)
        ERAISE(-EINVAL);

    /* create and initialize the request structure */
    {
        size_t extra = strlen(pathname) + 1;

        ECHECK((req_size = _new_request(sizeof(*req), extra, (void**)&req)));
        req->fs_cookie = proxyfs->fs_cookie;
        req->flags = flags;
        req->mode = mode;
        memcpy(req->pathname, pathname, extra);
    }

    /* call into the listener */
    ECHECK(myst_call_listener_helper(
        MYST_MESSAGE_OPEN,
        req,
        req_size,
        sizeof(*rsp),
        (void**)&rsp,
        &rsp_size));

    ECHECK(rsp->retval);

    /* allocate and initialize the new file system structure */
    ECHECK(myst_proxyfs_wrap(rsp->fs_cookie, &new_fs));

    /* allocate and initialize the new file structure */
    {
        if (!(new_file = calloc(1, sizeof(myst_file_t))))
            ERAISE(-ENOMEM);

        new_file->magic = FILE_MAGIC;
        new_file->file_cookie = rsp->file_cookie;
        new_file->use_count = 1;
    }

    *fs_out = new_fs;
    new_fs = NULL;

    *file_out = new_file;
    new_file = NULL;

done:

    if (new_file)
        free(new_file);

    if (new_fs)
        free(new_fs);

    if (req)
        free(req);

    if (rsp)
        free(rsp);

    return ret;
}

static off_t _fs_lseek(
    myst_fs_t* fs,
    myst_file_t* file,
    off_t offset,
    int whence)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.lseek.offset = offset;
    args.lseek.whence = whence;
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_LSEEK);
}

static ssize_t _fs_read(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(fs, file, &args, NULL, 0, buf, count, MYST_MESSAGE_READ);
}

static ssize_t _fs_write(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(fs, file, &args, buf, count, NULL, 0, MYST_MESSAGE_WRITE);
}

static ssize_t _fs_pread(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count,
    off_t offset)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.pread.offset = offset;
    long ret =
        _fileop(fs, file, &args, NULL, 0, buf, count, MYST_MESSAGE_PREAD);
    return ret;
}

static ssize_t _fs_pwrite(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count,
    off_t offset)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.pwrite.offset = offset;
    return _fileop(fs, file, &args, buf, count, NULL, 0, MYST_MESSAGE_PWRITE);
}

static ssize_t _fs_readv(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs) || !_file_valid(file))
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
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&fs->fdops, file, iov, iovcnt);
    ECHECK(ret);

done:
    return ret;
}

static int _fs_close(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs) || !_file_valid(file))
        ERAISE(-EINVAL);

    if (--file->use_count == 0)
    {
        myst_fileop_args_t args;
        memset(&args, 0, sizeof(args));
        ECHECK(_fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_CLOSE));
    }

done:
    return ret;
}

static int _fs_access(myst_fs_t* fs, const char* pathname, int mode)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    args.access.mode = mode;
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_ACCESS);
}

static int _fs_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    return _pathop(
        fs, pathname, &args, statbuf, sizeof(struct stat), MYST_MESSAGE_STAT);
}

static int _fs_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    return _pathop(
        fs, pathname, &args, statbuf, sizeof(struct stat), MYST_MESSAGE_LSTAT);
}

static int _fs_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(
        fs,
        file,
        &args,
        NULL,
        0,
        statbuf,
        sizeof(struct stat),
        MYST_MESSAGE_FSTAT);
}

static int _fs_link(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    return _twopathop(fs, oldpath, newpath, MYST_MESSAGE_LINK);
}

static int _fs_unlink(myst_fs_t* fs, const char* pathname)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_UNLINK);
}

static int _fs_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    return _twopathop(fs, oldpath, newpath, MYST_MESSAGE_RENAME);
}

static int _fs_truncate(myst_fs_t* fs, const char* pathname, off_t length)
{
    myst_pathop_args_t args;
    args.truncate.length = length;
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_TRUNCATE);
}

static int _fs_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.ftruncate.length = length;
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_FTRUNCATE);
}

static int _fs_mkdir(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    args.mkdir.mode = mode;
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_MKDIR);
}

static int _fs_rmdir(myst_fs_t* fs, const char* pathname)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_RMDIR);
}

static int _fs_getdents64(
    myst_fs_t* fs,
    myst_file_t* file,
    struct dirent* dirp,
    size_t count)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(
        fs, file, &args, NULL, 0, dirp, count, MYST_MESSAGE_GETDENTS64);
}

static ssize_t _fs_readlink(
    myst_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    return _pathop(fs, pathname, &args, buf, bufsiz, MYST_MESSAGE_READLINK);
}

static int _fs_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    return _twopathop(fs, target, linkpath, MYST_MESSAGE_SYMLINK);
}

static int _fs_realpath(
    myst_fs_t* fs,
    myst_file_t* file,
    char* buf,
    size_t size)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    long ret =
        _fileop(fs, file, &args, NULL, 0, buf, size, MYST_MESSAGE_REALPATH);
    return ret;
}

static int _fs_fcntl(myst_fs_t* fs, myst_file_t* file, int cmd, long arg)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.fcntl.cmd = cmd;
    args.fcntl.arg = arg;
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_FCNTL);
}

static int _fs_ioctl(
    myst_fs_t* fs,
    myst_file_t* file,
    unsigned long request,
    long arg)
{
    switch (request)
    {
        case TIOCGWINSZ:
            return -EINVAL;
        case FIOCLEX:
        case FIONCLEX:
            break;
        default:
            return -ENOTSUP;
    }

    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.ioctl.request = request;
    args.ioctl.arg = arg;
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_IOCTL);
}

static int _fs_dup(
    myst_fs_t* fs,
    const myst_file_t* file,
    myst_file_t** file_out)
{
    proxyfs_t* proxyfs = (proxyfs_t*)fs;
    int ret = 0;

    if (!_proxyfs_valid(proxyfs) || !_file_valid(file) || !file_out)
        ERAISE(-EINVAL);

    ((myst_file_t*)file)->use_count++;
    *file_out = (myst_file_t*)file;

done:

    return ret;
}

static int _fs_target_fd(myst_fs_t* fs, myst_file_t* file)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_TARGET_FD);
}

static int _fs_get_events(myst_fs_t* fs, myst_file_t* file)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_GET_EVENTS);
}

static int _fs_statfs(myst_fs_t* fs, const char* pathname, struct statfs* buf)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    return _pathop(
        fs, pathname, &args, buf, sizeof(struct statfs), MYST_MESSAGE_STATFS);
}

static int _fs_fstatfs(myst_fs_t* fs, myst_file_t* file, struct statfs* buf)
{
    myst_fileop_args_t args;
    const myst_message_type_t mt = MYST_MESSAGE_FSTATFS;
    memset(&args, 0, sizeof(args));
    return _fileop(fs, file, &args, NULL, 0, buf, sizeof(struct statfs), mt);
}

static int _fs_futimens(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct timespec times[2])
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.futimens.times[0] = times[0];
    args.futimens.times[1] = times[1];
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_FUTIMENS);
}

static int _fs_chown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    args.chown.owner = owner;
    args.chown.group = group;
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_CHOWN);
}

static int _fs_fchown(
    myst_fs_t* fs,
    myst_file_t* file,
    uid_t owner,
    gid_t group)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.fchown.owner = owner;
    args.fchown.group = group;
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_FCHOWN);
}

static int _fs_lchown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    args.lchown.owner = owner;
    args.lchown.group = group;
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_LCHOWN);
}

static int _fs_chmod(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    myst_pathop_args_t args;
    memset(&args, 0, sizeof(args));
    args.chmod.mode = mode;
    return _pathop(fs, pathname, &args, NULL, 0, MYST_MESSAGE_CHMOD);
}

static int _fs_fchmod(myst_fs_t* fs, myst_file_t* file, mode_t mode)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    args.fchmod.mode = mode;
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_FCHMOD);
}

static int _fs_fdatasync(myst_fs_t* fs, myst_file_t* file)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_FDATASYNC);
}

static int _fs_fsync(myst_fs_t* fs, myst_file_t* file)
{
    myst_fileop_args_t args;
    memset(&args, 0, sizeof(args));
    return _fileop(fs, file, &args, NULL, 0, NULL, 0, MYST_MESSAGE_FSYNC);
}

int myst_proxyfs_wrap(uint64_t fs_cookie, myst_fs_t** proxyfs_out)
{
    int ret = 0;
    proxyfs_t* proxyfs = NULL;
    static myst_fs_t _base = {
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
        .fs_id = _fs_id,
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
    };

    if (proxyfs_out)
        *proxyfs_out = NULL;

    if (!fs_cookie)
        ERAISE(-EINVAL);

    if (!(proxyfs = calloc(1, sizeof(proxyfs_t))))
        ERAISE(-ENOMEM);

    proxyfs->base = _base;
    proxyfs->magic = PROXYFS_MAGIC;
    proxyfs->fs_cookie = fs_cookie;
    *proxyfs_out = &proxyfs->base;

done:

    return ret;
}

int myst_proxyfile_wrap(uint64_t file_cookie, myst_file_t** file_out)
{
    int ret = 0;
    myst_file_t* file = NULL;

    if (file_out)
        *file_out = NULL;

    if (!file_cookie || !file_out)
        ERAISE(-EINVAL);

    if (!(file = calloc(1, sizeof(myst_file_t))))
        ERAISE(-ENOMEM);

    file->magic = FILE_MAGIC;
    file->file_cookie = file_cookie;
    file->use_count = 1;

    *file_out = file;
    file = NULL;

done:

    if (file)
        free(file);

    return ret;
}

bool myst_is_proxyfs(const myst_fs_t* fs)
{
    return _proxyfs_valid((const proxyfs_t*)fs);
}

int myst_proxy_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    myst_fs_t** fs_out)
{
    long ret = 0;
    myst_mount_resolve_request_t* req = NULL;
    size_t req_size;
    myst_mount_resolve_response_t* rsp = NULL;
    size_t rsp_size;
    myst_fs_t* fs;

    if (fs_out)
        *fs_out = NULL;

    if (!path || !suffix || !fs_out)
        ERAISE(-EINVAL);

    /* create the request structure */
    {
        size_t len = strlen(path);
        req_size = sizeof(*req) + len + 1;

        if (!(req = calloc(1, req_size)))
            ERAISE(-ENOMEM);

        myst_strlcpy(req->path, path, len + 1);
    }

    /* call into the listener */
    ECHECK(myst_listener_call(
        MYST_MESSAGE_MOUNT_RESOLVE, req, req_size, (void**)&rsp, &rsp_size));

    if (rsp_size <= sizeof(*rsp))
        ERAISE(-EINVAL);

    ECHECK(rsp->retval);

    if (!rsp->fs_cookie)
        ERAISE(-EINVAL);

    /* get the response suffix (check for null termination) */
    {
        size_t len = rsp_size - sizeof(*rsp) - 1;

        if (rsp->suffix[len] != '\0')
            ERAISE(-EINVAL);

        myst_strlcpy(suffix, rsp->suffix, PATH_MAX);
    }

    /* wrap the returned fs in a proxyfs */
    ECHECK(myst_proxyfs_wrap(rsp->fs_cookie, &fs));

    /* wrap the proxyfs in a lockfs */
    ECHECK(myst_lockfs_init(fs, fs_out));
    fs = NULL;

done:

    if (fs)
        (*fs->fs_release)(fs);

    if (req)
        free(req);

    if (rsp)
        free(rsp);

    return ret;
}
