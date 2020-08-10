#include <libos/file.h>
#include <libos/syscall.h>
#include <libos/strings.h>
#include <libos/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include "eraise.h"

int libos_creat(const char* pathname, mode_t mode)
{
    return (int)libos_syscall_ret(libos_syscall_creat(pathname, mode));
}

int libos_open(const char* pathname, int flags, mode_t mode)
{
    return (int)libos_syscall_ret(libos_syscall_open(pathname, flags, mode));
}

off_t libos_lseek(int fd, off_t offset, int whence)
{
    return (off_t)libos_syscall_ret(libos_syscall_lseek(fd, offset, whence));
}

int libos_close(int fd)
{
    return (int)libos_syscall_ret(libos_syscall_close(fd));
}

ssize_t libos_read(int fd, void* buf, size_t count)
{
    return (ssize_t)libos_syscall_ret(libos_syscall_read(fd, buf, count));
}

ssize_t libos_write(int fd, const void* buf, size_t count)
{
    return (ssize_t)libos_syscall_ret(libos_syscall_write(fd, buf, count));
}

ssize_t libos_readv(int fd, const struct iovec* iov, int iovcnt)
{
    return (ssize_t)libos_syscall_ret(libos_syscall_readv(fd, iov, iovcnt));
}

ssize_t libos_writev(int fd, const struct iovec* iov, int iovcnt)
{
    return (ssize_t)libos_syscall_ret(libos_syscall_writev(fd, iov, iovcnt));
}

int libos_stat(const char* pathname, struct stat* statbuf)
{
    return (int)libos_syscall_ret(libos_syscall_stat(pathname, statbuf));
}

int libos_lstat(const char* pathname, struct stat* statbuf)
{
    return (int)libos_syscall_ret(libos_syscall_lstat(pathname, statbuf));
}

int libos_fstat(int fd, struct stat* statbuf)
{
    return (int)libos_syscall_ret(libos_syscall_fstat(fd, statbuf));
}

int libos_mkdir(const char *pathname, mode_t mode)
{
    return (int)libos_syscall_ret(libos_syscall_mkdir(pathname, mode));
}

int libos_rmdir(const char* pathname)
{
    return (int)libos_syscall_ret(libos_syscall_rmdir(pathname));
}

int libos_getdents64(int fd, struct dirent* dirp, size_t count)
{
    return (int)libos_syscall_ret(libos_syscall_getdents64(fd, dirp, count));
}

int libos_link(const char* oldpath, const char* newpath)
{
    return (int)libos_syscall_ret(libos_syscall_link(oldpath, newpath));
}

int libos_unlink(const char* pathname)
{
    return (int)libos_syscall_ret(libos_syscall_unlink(pathname));
}

int libos_access(const char* pathname, int mode)
{
    return (int)libos_syscall_ret(libos_syscall_access(pathname, mode));
}

int libos_rename(const char* oldpath, const char* newpath)
{
    return (int)libos_syscall_ret(libos_syscall_rename(oldpath, newpath));
}

int libos_truncate(const char* path, off_t length)
{
    return (int)libos_syscall_ret(libos_syscall_truncate(path, length));
}

int libos_ftruncate(int fd, off_t length)
{
    return (int)libos_syscall_ret(libos_syscall_ftruncate(fd, length));
}

ssize_t libos_readlink(const char* pathname, char* buf, size_t bufsiz)
{
    return (int)libos_syscall_ret(libos_syscall_readlink(pathname, buf, bufsiz));
}

int libos_symlink(const char* target, const char* linkpath)
{
    return (int)libos_syscall_ret(libos_syscall_symlink(target, linkpath));
}

int libos_mkdirhier(const char* pathname, mode_t mode)
{
    int ret = 0;
    char** toks = NULL;
    size_t ntoks;
    char path[PATH_MAX];
    const bool trace = libos_get_trace();
    struct stat buf;

    libos_set_trace(false);

    if (!pathname)
        ERAISE(-EINVAL);

    /* If the directory already exists, stop here */
    if (libos_stat(pathname, &buf) == 0 && S_ISDIR(buf.st_mode))
        goto done;

    ECHECK(libos_strsplit(pathname, "/", &toks, &ntoks));

    *path = '\0';

    for (size_t i = 0; i < ntoks; i++)
    {
        if (LIBOS_STRLCAT(path, "/") >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        if (LIBOS_STRLCAT(path, toks[i]) >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        if (libos_stat(path, &buf) == 0)
        {
            if (!S_ISDIR(buf.st_mode))
                ERAISE(-ENOTDIR);
        }
        else
        {
            ECHECK(libos_mkdir(path, mode));
        }
    }

    if (libos_stat(pathname, &buf) != 0 || !S_ISDIR(buf.st_mode))
        ERAISE(-EPERM);

done:

    if (toks)
        free(toks);

    libos_set_trace(trace);

    return ret;
}
