#include <libos/file.h>
#include <libos/syscall.h>
#include <stdio.h>

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
