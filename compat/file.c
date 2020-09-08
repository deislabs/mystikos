#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <libos/file.h>
#include <libos/eraise.h>
#include <libos/strings.h>
#include <libos/malloc.h>
#include <string.h>

int libos_creat(const char* pathname, mode_t mode)
{
    return creat(pathname, mode);
}

int libos_open(const char* pathname, int flags, mode_t mode)
{
    return open(pathname, flags, mode);
}

off_t libos_lseek(int fd, off_t offset, int whence)
{
    return lseek(fd, offset, whence);
}

int libos_close(int fd)
{
    return close(fd);
}

ssize_t libos_read(int fd, void* buf, size_t count)
{
    return read(fd, buf, count);
}

ssize_t libos_write(int fd, const void* buf, size_t count)
{
    return write(fd, buf, count);
}

ssize_t libos_readv(int fd, const struct iovec* iov, int iovcnt)
{
    return readv(fd, iov, iovcnt);
}

ssize_t libos_writev(int fd, const struct iovec* iov, int iovcnt)
{
    return writev(fd, iov, iovcnt);
}

int libos_stat(const char* pathname, struct stat* statbuf)
{
    return stat(pathname, statbuf);
}

int libos_lstat(const char* pathname, struct stat* statbuf)
{
    return lstat(pathname, statbuf);
}

int libos_fstat(int fd, struct stat* statbuf)
{
    return fstat(fd, statbuf);
}

int libos_mkdir(const char *pathname, mode_t mode)
{
    return mkdir(pathname, mode);
}

int libos_rmdir(const char* pathname)
{
    return rmdir(pathname);
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
    return link(oldpath, newpath);
}

int libos_unlink(const char* pathname)
{
    return unlink(pathname);
}

int libos_access(const char* pathname, int mode)
{
    return access(pathname, mode);
}

int libos_rename(const char* oldpath, const char* newpath)
{
    return rename(oldpath, newpath);
}

int libos_truncate(const char* path, off_t length)
{
    return truncate(path, length);
}

int libos_ftruncate(int fd, off_t length)
{
    return ftruncate(fd, length);
}

ssize_t libos_readlink(const char* pathname, char* buf, size_t bufsiz)
{
    return readlink(pathname, buf, bufsiz);
}

int libos_symlink(const char* target, const char* linkpath)
{
    return symlink(target, linkpath);
}

int libos_mkdirhier(const char* pathname, mode_t mode)
{
    int ret = 0;
    char path[PATH_MAX];
    struct stat buf;
    char* clone;
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
