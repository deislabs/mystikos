// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_SYSCALL_H
#define _LIBOS_SYSCALL_H

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>

#include <libos/defs.h>
#include <libos/syscallext.h>

LIBOS_INLINE long libos_syscall0(long n)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

LIBOS_INLINE long libos_syscall1(long n, long x1)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

LIBOS_INLINE long libos_syscall2(long n, long x1, long x2)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

LIBOS_INLINE long libos_syscall3(long n, long x1, long x2, long x3)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

LIBOS_INLINE long libos_syscall4(long n, long x1, long x2, long x3, long x4)
{
    unsigned long ret;
    register long r10 __asm__("r10") = x4;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3), "r"(r10)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

LIBOS_INLINE long
libos_syscall5(long n, long x1, long x2, long x3, long x4, long x5)
{
    unsigned long ret;
    register long r10 __asm__("r10") = x4;
    register long r8 __asm__("r8") = x5;
    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3), "r"(r10), "r"(r8)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

LIBOS_INLINE long
libos_syscall6(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    unsigned long ret;
    register long r10 __asm__("r10") = x4;
    register long r8 __asm__("r8") = x5;
    register long r9 __asm__("r9") = x6;

    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(x1), "S"(x2), "d"(x3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");

    return (long)ret;
}

long libos_syscall(long n, long params[6]);

const char* syscall_str(long n);

void libos_set_rootfs(const char* path);

long libos_syscall_ret(long r);

long libos_syscall(long n, long params[6]);

long libos_syscall_creat(const char* pathname, mode_t mode);

long libos_syscall_open(const char* pathname, int flags, mode_t mode);

long libos_syscall_lseek(int fd, off_t offset, int whence);

long libos_syscall_close(int fd);

long libos_syscall_read(int fd, void* buf, size_t count);

long libos_syscall_write(int fd, const void* buf, size_t count);

long libos_syscall_pread(int fd, void* buf, size_t count, off_t offset);

long libos_syscall_pwrite(int fd, const void* buf, size_t count, off_t offset);

long libos_syscall_readv(int fd, const struct iovec* iov, int iovcnt);

long libos_syscall_writev(int fd, const struct iovec* iov, int iovcnt);

long libos_syscall_stat(const char* pathname, struct stat* statbuf);

long libos_syscall_lstat(const char* pathname, struct stat* statbuf);

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

long libos_syscall_readlink(const char* pathname, char* buf, size_t bufsiz);

long libos_syscall_symlink(const char* target, const char* linkpath);

long libos_syscall_chdir(const char* path);

long libos_syscall_getcwd(char* buf, size_t size);

long libos_syscall_fcntl(int fd, int cmd, long arg);

long libos_syscall_add_symbol_file(
    const char* path,
    const void* text,
    size_t text_size);

long libos_syscall_load_symbols(void);

long libos_syscall_unload_symbols(void);

long libos_syscall_clock_gettime(clockid_t clk_id, struct timespec* tp);

long libos_syscall_clock_settime(clockid_t clk_id, struct timespec* tp);

long libos_syscall_gettimeofday(struct timeval* tv, struct timezone* tz);

long libos_syscall_time(time_t* tloc);

long libos_syscall_clone(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg,
    pid_t* ptid,
    void* newtls,
    pid_t* ctid);

long libos_syscall_futex(
    int* uaddr,
    int op,
    int val,
    long arg, /* timeout or val2 */
    int* uaddr2,
    int val3);

long libos_syscall_getrandom(void* buf, size_t buflen, unsigned int flags);

struct rusage;

long libos_syscall_wait4(
    pid_t pid,
    int* wstatus,
    int options,
    struct rusage* rusage);

long libos_syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout);

long libos_syscall_select(
    int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout);

long libos_syscall_nanosleep(const struct timespec* req, struct timespec* rem);

#endif /* _LIBOS_SYSCALL_H */
