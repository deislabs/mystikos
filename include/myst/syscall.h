// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SYSCALL_H
#define _MYST_SYSCALL_H

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

#include <myst/defs.h>
#include <myst/syscallext.h>

MYST_INLINE long myst_syscall0(long n)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

MYST_INLINE long myst_syscall1(long n, long x1)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

MYST_INLINE long myst_syscall2(long n, long x1, long x2)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

MYST_INLINE long myst_syscall3(long n, long x1, long x2, long x3)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

MYST_INLINE long myst_syscall4(long n, long x1, long x2, long x3, long x4)
{
    unsigned long ret;
    register long r10 __asm__("r10") = x4;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3), "r"(r10)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

MYST_INLINE long
myst_syscall5(long n, long x1, long x2, long x3, long x4, long x5)
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

MYST_INLINE long
myst_syscall6(long n, long x1, long x2, long x3, long x4, long x5, long x6)
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

long myst_syscall(long n, long params[6]);

const char* syscall_str(long n);

void myst_set_rootfs(const char* path);

long myst_syscall_ret(long r);

long myst_syscall(long n, long params[6]);

long myst_syscall_creat(const char* pathname, mode_t mode);

long myst_syscall_open(const char* pathname, int flags, mode_t mode);

long myst_syscall_lseek(int fd, off_t offset, int whence);

long myst_syscall_close(int fd);

long myst_syscall_read(int fd, void* buf, size_t count);

long myst_syscall_write(int fd, const void* buf, size_t count);

long myst_syscall_pread(int fd, void* buf, size_t count, off_t offset);

long myst_syscall_pwrite(int fd, const void* buf, size_t count, off_t offset);

long myst_syscall_readv(int fd, const struct iovec* iov, int iovcnt);

long myst_syscall_writev(int fd, const struct iovec* iov, int iovcnt);

long myst_syscall_stat(const char* pathname, struct stat* statbuf);

long myst_syscall_lstat(const char* pathname, struct stat* statbuf);

long myst_syscall_fstat(int fd, struct stat* statbuf);

long myst_syscall_mkdir(const char* pathname, mode_t mode);

long myst_syscall_getdents64(int fd, struct dirent* dirp, size_t count);

long myst_syscall_rmdir(const char* pathname);

long myst_syscall_link(const char* oldpath, const char* newpath);

long myst_syscall_unlink(const char* pathname);

long myst_syscall_access(const char* pathname, int mode);

long myst_syscall_rename(const char* oldpath, const char* newpath);

long myst_syscall_truncate(const char* path, off_t length);

long myst_syscall_ftruncate(int fd, off_t length);

long myst_syscall_readlink(const char* pathname, char* buf, size_t bufsiz);

long myst_syscall_symlink(const char* target, const char* linkpath);

long myst_syscall_chdir(const char* path);

long myst_syscall_getcwd(char* buf, size_t size);

long myst_syscall_fcntl(int fd, int cmd, long arg);

long myst_syscall_add_symbol_file(
    const char* path,
    const void* text,
    size_t text_size);

long myst_syscall_load_symbols(void);

long myst_syscall_unload_symbols(void);

long myst_syscall_clock_getres(clockid_t clk_id, struct timespec* res);

long myst_syscall_clock_gettime(clockid_t clk_id, struct timespec* tp);

long myst_syscall_clock_settime(clockid_t clk_id, struct timespec* tp);

long myst_syscall_gettimeofday(struct timeval* tv, struct timezone* tz);

long myst_syscall_time(time_t* tloc);

long myst_syscall_clone(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg,
    pid_t* ptid,
    void* newtls,
    pid_t* ctid);

long myst_syscall_futex(
    int* uaddr,
    int op,
    int val,
    long arg, /* timeout or val2 */
    int* uaddr2,
    int val3);

long myst_syscall_getrandom(void* buf, size_t buflen, unsigned int flags);

struct rusage;

long myst_syscall_wait4(
    pid_t pid,
    int* wstatus,
    int options,
    struct rusage* rusage);

long myst_syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout);

long myst_syscall_select(
    int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout);

long myst_syscall_nanosleep(const struct timespec* req, struct timespec* rem);

long myst_syscall_exit_group(int status);

long myst_syscall_tgkill(int tgid, int tid, int sig);

long myst_syscall_mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data);

long myst_syscall_umount2(const char* target, int flags);
long myst_syscall_kill(int pid, int sig);

long myst_syscall_sethostname(const char* hostname, size_t len);

long myst_syscall_kill(int pid, int sig);

long myst_syscall_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

long myst_syscall_sethostname(const char* hostname, size_t len);

#endif /* _MYST_SYSCALL_H */
