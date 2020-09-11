#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <libos/file.h>
#include <libos/eraise.h>
#include <libos/strings.h>
#include <libos/malloc.h>
#include <string.h>

/* ATTN: the kernel-version of these functions return -errno */

static long _ret(long ret)
{
    if (ret < 0)
        ret = -errno;

    return ret;
}

int libos_creat(const char* pathname, mode_t mode)
{
    return (int)_ret(creat(pathname, mode));
}

int libos_open(const char* pathname, int flags, mode_t mode)
{
    return (int)_ret(open(pathname, flags, mode));
}

off_t libos_lseek(int fd, off_t offset, int whence)
{
    return (off_t)_ret(lseek(fd, offset, whence));
}

int libos_close(int fd)
{
    return (int)_ret(close(fd));
}

ssize_t libos_read(int fd, void* buf, size_t count)
{
    return (ssize_t)_ret(read(fd, buf, count));
}

ssize_t libos_write(int fd, const void* buf, size_t count)
{
    return (ssize_t)_ret(write(fd, buf, count));
}

ssize_t libos_readv(int fd, const struct iovec* iov, int iovcnt)
{
    return (ssize_t)_ret(readv(fd, iov, iovcnt));
}

ssize_t libos_writev(int fd, const struct iovec* iov, int iovcnt)
{
    return (ssize_t)_ret(writev(fd, iov, iovcnt));
}

int libos_stat(const char* pathname, struct stat* statbuf)
{
    return (int)_ret(stat(pathname, statbuf));
}

int libos_lstat(const char* pathname, struct stat* statbuf)
{
    return (int)_ret(lstat(pathname, statbuf));
}

int libos_fstat(int fd, struct stat* statbuf)
{
    return (int)_ret(fstat(fd, statbuf));
}

int libos_mkdir(const char *pathname, mode_t mode)
{
    return (int)_ret(mkdir(pathname, mode));
}

int libos_rmdir(const char* pathname)
{
    return (int)_ret(rmdir(pathname));
}

#if 0
int libos_getdents64(int fd, struct dirent* dirp, size_t count)
{
    long r;

    if ((r = syscall(SYS_getdents64, fd, dirp, count)) < 0)
    {
        errno = (int)-r;
        return -1;
    }

    return (int)r;
}
#endif

int libos_link(const char* oldpath, const char* newpath)
{
    return (int)_ret(link(oldpath, newpath));
}

int libos_unlink(const char* pathname)
{
    return (int)_ret(unlink(pathname));
}

int libos_access(const char* pathname, int mode)
{
    return (int)_ret(access(pathname, mode));
}

int libos_rename(const char* oldpath, const char* newpath)
{
    return (int)_ret(rename(oldpath, newpath));
}

int libos_truncate(const char* path, off_t length)
{
    return (int)_ret(truncate(path, length));
}

int libos_ftruncate(int fd, off_t length)
{
    return (int)_ret(ftruncate(fd, length));
}

ssize_t libos_readlink(const char* pathname, char* buf, size_t bufsiz)
{
    return (size_t)_ret(readlink(pathname, buf, bufsiz));
}

int libos_symlink(const char* target, const char* linkpath)
{
    return (int)_ret(symlink(target, linkpath));
}

int libos_mkdirhier(const char* pathname, mode_t mode)
{
    int ret = 0;
    char path[PATH_MAX];
    struct stat buf;
    char* clone = NULL;
    char* p;
    char* save;

    if (!pathname)
        ERAISE(-EINVAL);

    /* If a file or directory with this name already exits */
    if (stat(pathname, &buf) == 0)
    {
        if (!S_ISDIR(buf.st_mode))
            ERAISE(-ENOTDIR);

        goto done;
    }

    if (!(clone = strdup(pathname)))
        ERAISE(-ENOMEM);

    *path = '\0';

    for (p = strtok_r(clone, "/", &save); p; p = strtok_r(NULL, "/", &save))
    {
        if (*pathname == '/' || *path != '\0')
        {
            if (libos_strlcat(path, "/", sizeof(path)) >= PATH_MAX)
                ERAISE(-ENAMETOOLONG);
        }

        if (libos_strlcat(path, p, sizeof(path)) >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        if (stat(path, &buf) == 0)
        {
            if (!S_ISDIR(buf.st_mode))
                ERAISE(-ENOTDIR);
        }
        else
        {
            ECHECK(mkdir(path, mode));
        }
    }

    if (stat(pathname, &buf) != 0 || !S_ISDIR(buf.st_mode))
        ERAISE(-EPERM);

done:

    if (clone)
        libos_free(clone);

    return ret;
}
