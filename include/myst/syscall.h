// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SYSCALL_H
#define _MYST_SYSCALL_H

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>

#include <myst/defs.h>
#include <myst/thread.h>

#define UDP_PACKET_MAX_LENGTH (75 * 1024)

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

void myst_set_rootfs(const char* path);

long myst_syscall_ret(long r);

long myst_syscall(long n, long params[6]);

long myst_syscall_creat(const char* pathname, mode_t mode);

long myst_syscall_open(const char* pathname, int flags, mode_t mode);

long myst_syscall_openat(
    int dirfd,
    const char* pathname,
    int flags,
    mode_t mode);

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

long myst_syscall_mkdirat(int dirfd, const char* pathname, mode_t mode);

long myst_syscall_getdents64(int fd, struct dirent* dirp, size_t count);

long myst_syscall_rmdir(const char* pathname);

long _myst_syscall_link_flags(
    const char* oldpath,
    const char* newpath,
    int flags);

long myst_syscall_link(const char* oldpath, const char* newpath);

long myst_syscall_unlink(const char* pathname);

long myst_syscall_unlinkat(int dirfd, const char* pathname, int flags);

long myst_syscall_access(const char* pathname, int mode);

long myst_syscall_rename(const char* oldpath, const char* newpath);

long myst_syscall_truncate(const char* path, off_t length);

long myst_syscall_ftruncate(int fd, off_t length);

long myst_syscall_readlink(const char* pathname, char* buf, size_t bufsiz);

long myst_syscall_symlink(const char* target, const char* linkpath);

long myst_syscall_chdir(const char* path);

long myst_syscall_getcwd(char* buf, size_t size);

long myst_syscall_fcntl(int fd, int cmd, long arg);

long myst_syscall_dup(int fd);

long myst_syscall_chmod(const char* pathname, mode_t mode);

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

long myst_syscall_sched_getparam(pid_t pid, struct sched_param* param);
long myst_syscall_getrandom(void* buf, size_t buflen, unsigned int flags);

struct rusage;

long myst_syscall_wait4(
    pid_t pid,
    int* wstatus,
    int options,
    struct rusage* rusage);

long myst_syscall_waitid(
    idtype_t idtype,
    id_t id,
    siginfo_t* infop,
    int options);

long myst_syscall_poll(
    struct pollfd* fds,
    nfds_t nfds,
    int timeout,
    bool fail_badf);

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
    const void* data,
    bool is_auto);

long myst_syscall_umount2(const char* target, int flags);
long myst_syscall_kill(int pid, int sig);

long myst_syscall_sethostname(const char* hostname, size_t len);

long myst_syscall_kill(int pid, int sig);

long myst_syscall_sendfile(int out_fd, int in_fd, off_t* offset, size_t count);

long myst_syscall_copy_file_range(
    int fd_in,
    off_t* off_in,
    int fd_out,
    off_t* off_out,
    size_t len,
    unsigned int flags);

long myst_syscall_sethostname(const char* hostname, size_t len);

long myst_syscall_umask(mode_t mask);

long myst_syscall_run_itimer(myst_process_t* process);

long myst_syscall_setitimer(
    myst_process_t* process,
    int which,
    const struct itimerval* new_value,
    struct itimerval* old_value);

int myst_syscall_getitimer(
    myst_process_t* process,
    int which,
    struct itimerval* curr_value);

long myst_syscall_fsync(int fd);

long myst_syscall_uname(struct utsname* buf);

long myst_syscall_getuid();
long myst_syscall_setuid(uid_t uid);

long myst_syscall_getgid();
long myst_syscall_setgid(gid_t gid);

long myst_syscall_setsid();

uid_t myst_syscall_geteuid();
gid_t myst_syscall_getegid();

long myst_syscall_setreuid(uid_t ruid, uid_t euid);
long myst_syscall_setregid(gid_t rgid, gid_t egid);

long myst_syscall_getresuid(uid_t* ruid, uid_t* euid, uid_t* savuid);
long myst_syscall_setresuid(uid_t ruid, uid_t euid, uid_t savuid);

long myst_syscall_getresgid(gid_t* rgid, gid_t* egid, gid_t* savgid);
long myst_syscall_setresgid(uid_t rgid, uid_t egid, uid_t savgid);

long myst_syscall_setfsuid(uid_t fsuid);
long myst_syscall_setfsgid(gid_t fsgid);

long myst_syscall_getgroups(int size, gid_t list[]);
long myst_syscall_setgroups(size_t size, const gid_t* list);

long myst_syscall_sched_getaffinity(
    pid_t pid,
    size_t cpusetsize,
    cpu_set_t* mask);

long myst_syscall_sched_setaffinity(
    pid_t pid,
    size_t cpusetsize,
    const cpu_set_t* mask);

long myst_syscall_getcpu(unsigned* cpu, unsigned* node);

long myst_syscall_chown(const char* pathname, uid_t owner, gid_t group);
long myst_syscall_fchown(int fd, uid_t owner, gid_t group);
long myst_syscall_lchown(const char* pathname, uid_t owner, gid_t group);
long myst_syscall_fchownat(
    int dirfd,
    const char* pathname,
    uid_t owner,
    gid_t group,
    int flags);

#define FB_PATH_NOT_EMPTY 0x0000
#define FB_TYPE_FILE 0x0001
#define FB_TYPE_DIRECTORY 0x0010
#define FB_THROW_ERROR_NOFOLLOW 0x00010000

/* Used by XXXXXat() syscalls */
long myst_get_absolute_path_from_dirfd(
    int dirfd,
    const char* pathname,
    int flags,
    char** abspath_out,
    const int flags_behavior);

long myst_syscall_get_process_stack(void** stack, size_t* stack_size);

long myst_syscall_setpgid(pid_t pid, pid_t pgid, myst_thread_t* thread);
long myst_syscall_getpgid(pid_t pid, myst_thread_t* thread);

long myst_syscall_pause(void);

long myst_syscall_interrupt_thread(int tid);

/* interruptible by myst_syscall_interrupt_thread() */
long myst_interruptible_syscall(
    long n,       /* syscall number */
    int fd,       /* file descriptor to be interrupted */
    short events, /* events passed to ppoll() (POLLIN, POLLOUT) */
    bool retry,   /* whether to retry the operation on EAGAIN/EINPROGRESS */
    ...);

/* get the syscall name for the given syscall number */
const char* myst_syscall_name(long num);

/* get the syscall number for the given syscall name */
long myst_syscall_num(const char* name);

typedef struct myst_syscall_pair
{
    short num;
    const char* name;
} myst_syscall_pair_t;

const myst_syscall_pair_t* myst_syscall_pairs(void);

#define SYSCALL_GROUP_MAX_SIZE 128

/* Stores the syscall group name, corresponding syscalls, and number of syscalls
 */
typedef struct myst_syscall_group
{
    const char* name;
    const size_t group_size;
    const int syscalls[SYSCALL_GROUP_MAX_SIZE];
} myst_syscall_group_t;

const int* myst_syscall_group(const char* name);

size_t myst_syscall_group_size(const char* name);

#endif /* _MYST_SYSCALL_H */
