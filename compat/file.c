#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <libos/file.h>

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
