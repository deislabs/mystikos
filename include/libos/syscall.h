#ifndef _LIBOS_SYSCALL_H
#define _LIBOS_SYSCALL_H

#include <sys/syscall.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdbool.h>

enum
{
    LIBOS_SYS_base = 1024,
    LIBOS_SYS_trace,
    LIBOS_SYS_trace_ptr,
    LIBOS_SYS_dump_stack,
    LIBOS_SYS_dump_ehdr,
};

void libos_trace_syscalls(bool flag);

long libos_syscall(long n, long params[6]);

const char* syscall_str(long n);

int libos_get_exit_status(void);

int libos_set_exit_jump(void);

void libos_set_rootfs(const char* path);

long libos_syscall_ret(long r);

long libos_syscall(long n, long params[6]);

long libos_syscall_creat(const char* pathname, mode_t mode);

long libos_syscall_open(const char* pathname, int flags, mode_t mode);

long libos_syscall_lseek(int fd, off_t offset, int whence);

long libos_syscall_close(int fd);

long libos_syscall_read(int fd, void* buf, size_t count);

long libos_syscall_write(int fd, const void* buf, size_t count);

long libos_syscall_readv(int fd, struct iovec* iov, int iovcnt);

long libos_syscall_writev(int fd, const struct iovec* iov, int iovcnt);

long libos_syscall_stat(const char* pathname, struct stat* statbuf);

long libos_syscall_fstat(int fd, struct stat* statbuf);

long libos_syscall_mkdir(const char* pathname, mode_t mode);

long libos_syscall_getdents64(int fd, struct dirent* dirp, size_t count);

long libos_syscall_rmdir(const char* pathname);

long libos_syscall_link(const char* oldpath, const char* newpath);

long libos_syscall_unlink(const char* pathname);

long libos_syscall_access(const char* pathname, int mode);

long libos_syscall_rename(const char* oldpath, const char* newpath);

long libos_syscall_truncate(const char* path, off_t length);

long libos_syscall_ftruncate(int fd, off_t length);

#endif /* _LIBOS_SYSCALL_H */
