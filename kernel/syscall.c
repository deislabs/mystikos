// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <myst/mman.h>
#include <myst/mmanutils.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <myst/backtrace.h>
#include <myst/barrier.h>
#include <myst/blkdev.h>
#include <myst/buf.h>
#include <myst/bufalloc.h>
#include <myst/clock.h>
#include <myst/cpio.h>
#include <myst/cwd.h>
#include <myst/epolldev.h>
#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/eventfddev.h>
#include <myst/exec.h>
#include <myst/ext2.h>
#include <myst/fdops.h>
#include <myst/fdtable.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/fsgs.h>
#include <myst/gcov.h>
#include <myst/hex.h>
#include <myst/hostfs.h>
#include <myst/id.h>
#include <myst/initfini.h>
#include <myst/inotifydev.h>
#include <myst/iov.h>
#include <myst/kernel.h>
#include <myst/kstack.h>
#include <myst/libc.h>
#include <myst/lockfs.h>
#include <myst/lsr.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/msg.h>
#include <myst/once.h>
#include <myst/options.h>
#include <myst/panic.h>
#include <myst/paths.h>
#include <myst/pipedev.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/pubkey.h>
#include <myst/ramfs.h>
#include <myst/realpath.h>
#include <myst/round.h>
#include <myst/setjmp.h>
#include <myst/signal.h>
#include <myst/sockdev.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/syscallext.h>
#include <myst/syslog.h>
#include <myst/tcall.h>
#include <myst/tee.h>
#include <myst/thread.h>
#include <myst/time.h>
#include <myst/times.h>
#include <myst/trace.h>

#define MAX_IPADDR_LEN 64

#define COLOR_RED "\e[31m"
#define COLOR_BLUE "\e[34m"
#define COLOR_GREEN "\e[32m"
#define COLOR_RESET "\e[0m"

long myst_syscall_isatty(int fd);

static bool _iov_bad_addr(const struct iovec* iov, int iovcnt)
{
    if (iov)
    {
        for (int i = 0; i < iovcnt; i++)
        {
            const struct iovec* v = &iov[i];

            if (v->iov_len && myst_is_bad_addr_read(v->iov_base, v->iov_len))
                return true;
        }
    }

    return false;
}

long myst_syscall_get_fork_info(myst_process_t* process, myst_fork_info_t* arg)
{
    long ret = 0;

    /* preinitialize this in case something goes wrong */
    if (arg)
        *arg = (myst_fork_info_t)MYST_FORK_INFO_INITIALIZER;

    if (!arg)
        ERAISE(-EINVAL);

    arg->fork_mode = __myst_kernel_args.fork_mode;

    if (arg->fork_mode == myst_fork_none)
    {
        arg->is_child_fork = false;
        arg->is_parent_of_fork = false;
    }
    else
    {
        /* Check if we are child fork by looking at clone flag */
        arg->is_child_fork = process->is_pseudo_fork_process;

        /* Check if we have a child process which is a clone */
        arg->is_parent_of_fork = process->is_parent_of_pseudo_fork_process;
    }
#if 0
    printf(
        "pid=%d, forkmode=%s, is_child_fork=%s, is_parent_of_fork=%s\n",
        myst_getpid(),
        arg->fork_mode == myst_fork_none
            ? "none"
            : arg->fork_mode == myst_fork_pseudo ? "pseudo" : "pseudo-wait",
        arg->is_child_fork ? "yes" : "no",
        arg->is_parent_of_fork ? "yes" : "no");
#endif
done:
    return ret;
}

static const char* _syscall_str(long n)
{
    const char* name = myst_syscall_name(n);
    return name ? name : "unknown";
}

const char* myst_syscall_str(long n)
{
    return _syscall_str(n);
}

struct timespec_buf
{
    char data[72];
};

/* format a timespec structure */
static const char* _format_timespec(
    struct timespec_buf* buf,
    const struct timespec* ts)
{
    if (ts && myst_is_addr_within_kernel(ts))
    {
        snprintf(
            buf->data,
            sizeof(buf->data),
            "%p(sec=%ld nsec=%ld)",
            ts,
            ts->tv_sec,
            ts->tv_nsec);
    }
    else
    {
        snprintf(buf->data, sizeof(buf->data), "%p", ts);
    }

    return buf->data;
}

static bool _trace_syscall(long n)
{
    // Check if syscall tracing is enabled.
    if (__myst_kernel_args.strace_config.trace_syscalls)
    {
        if (__myst_kernel_args.strace_config.filter)
        {
            // If filtering is enabled, trace only this syscall has been
            // specified in the filter.
            return __myst_kernel_args.strace_config.trace[n];
        }
        else
        {
            // Trace all syscalls.
            return true;
        }
    }
    return false;
}

static void _syscall_failure_hook(long n, long ret)
{
    // Set breakpoint in this function to stop execution when a syscall fails.
    // Set condition for the breakpoint to control which syscall failures
    // trigger the breakpoint.
    (void)n;
    (void)ret;
}

static bool _trace_syscall_return(long n, long ret)
{
    // If this syscall has been configured to be traced, then trace the return
    // too.
    if (_trace_syscall(n))
        return true;

    // Check if tracing failing syscalls has been enabled.
    if (__myst_kernel_args.strace_config.trace_failing)
    {
        // If the syscall returns a negative value and has a valid error name,
        // then consider it a failure and enable tracing.
        if (ret < 0)
        {
            const char* error_name = myst_error_name(-ret);
            if (error_name)
                return true;
        }
    }
    return false;
}

__attribute__((format(printf, 2, 3))) static void _strace(
    long n,
    const char* fmt,
    ...)
{
    if (_trace_syscall(n))
    {
        char null_char = '\0';
        char* buf = &null_char;
        const bool isatty = myst_syscall_isatty(STDERR_FILENO) == 1;
        const char* blue = isatty ? COLOR_GREEN : "";
        const char* reset = isatty ? COLOR_RESET : "";

        if (fmt)
        {
            const size_t buf_size = 1024;

            if (!(buf = malloc(buf_size)))
                myst_panic("out of memory");

            va_list ap;
            va_start(ap, fmt);
            vsnprintf(buf, buf_size, fmt, ap);
            va_end(ap);
        }

        myst_eprintf(
            "=== %s%s%s(%s): pid=%d tid=%d\n",
            blue,
            _syscall_str(n),
            reset,
            buf,
            myst_getpid(),
            myst_gettid());

        if (buf != &null_char)
            free(buf);
    }
}

long myst_syscall_unmap_on_exit(myst_thread_t* thread, void* ptr, size_t size)
{
    long ret = 0;
    int i = thread->unmap_on_exit_used++;
    if (i >= MYST_MAX_MUNNAP_ON_EXIT)
    {
        thread->unmap_on_exit_used--;
        ret = -ENOMEM;
    }
    else
    {
        thread->unmap_on_exit[i].ptr = ptr;
        thread->unmap_on_exit[i].size = size;
    }
    return ret;
}

static long _forward_syscall(long n, long params[6])
{
    if (_trace_syscall(n))
        myst_eprintf("    [forward syscall]\n");

    return myst_tcall(n, params);
}

typedef struct fd_entry
{
    int fd;
    char path[PATH_MAX];
} fd_entry_t;

static long _return(long n, long ret)
{
    if (_trace_syscall_return(n, ret))
    {
        const char* red = "";
        const char* reset = "";
        const char* error_name = NULL;

        if (ret < 0)
        {
            const bool isatty = myst_syscall_isatty(STDERR_FILENO) == 1;

            if (isatty)
            {
                red = COLOR_RED;
                reset = COLOR_RESET;
            }

            error_name = myst_error_name(-ret);
        }

        if (error_name)
        {
            myst_eprintf(
                "    %s%s(): return=-%s(%ld)%s: pid=%d tid=%d\n",
                red,
                _syscall_str(n),
                error_name,
                ret,
                reset,
                myst_getpid(),
                myst_gettid());

            // Trigger breakpoint if set.
            _syscall_failure_hook(n, ret);
        }
        else
        {
            myst_eprintf(
                "    %s%s(): return=%ld(%lx)%s: pid=%d tid=%d\n",
                red,
                _syscall_str(n),
                ret,
                ret,
                reset,
                myst_getpid(),
                myst_gettid());
        }
    }

    return ret;
}

static int _socketaddr_to_str(
    const struct sockaddr* addr,
    char out[],
    size_t limit)
{
    int ret = 0;

    if (addr == NULL)
    {
        myst_assume(limit >= 5);
        myst_strlcpy(out, "NULL", limit);
        goto done;
    }

    if (myst_is_bad_addr_read(addr, sizeof(struct sockaddr)))
    {
        myst_assume(limit >= 6);
        myst_strlcpy(out, "INVAL", limit);
        ERAISE(-EFAULT);
    }

    const uint8_t* p = (uint8_t*)addr->sa_data;
    uint16_t port = (uint16_t)((p[0] << 8) | p[1]);
    const uint8_t ip1 = p[2];
    const uint8_t ip2 = p[3];
    const uint8_t ip3 = p[4];
    const uint8_t ip4 = p[5];

    if (snprintf(out, limit, "%u.%u.%u.%u:%u", ip1, ip2, ip3, ip4, port) >=
        (int)limit)
    {
        ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

long myst_syscall_creat(const char* pathname, mode_t mode)
{
    long ret = 0;
    int fd;
    myst_fs_t *fs, *fs_out;
    myst_file_t* file;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_FILE;
    long r;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_creat)(fs, locals->suffix, mode, &fs_out, &file));

    if ((fd = myst_fdtable_assign(fdtable, fdtype, fs_out, file)) < 0)
    {
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(fd);
    }

    if ((r = myst_add_fd_link(fs_out, file, fd)) != 0)
    {
        myst_fdtable_remove(fdtable, fd);
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(r);
    }

    ret = fd;

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_open(const char* pathname, int flags, mode_t mode)
{
    long ret = 0;
    myst_fs_t *fs, *fs_out;
    myst_file_t* file;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_FILE;
    int fd;
    int r;
    struct locals
    {
        char suffix[PATH_MAX];
        struct stat statbuf;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_open)(fs, locals->suffix, flags, mode, &fs_out, &file));

    myst_assume(myst_is_hostfs(fs_out) || myst_is_lockfs(fs_out));

    if ((fd = myst_fdtable_assign(fdtable, fdtype, fs_out, file)) < 0)
    {
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(fd);
    }

    if ((r = myst_add_fd_link(fs_out, file, fd)) != 0)
    {
        myst_fdtable_remove(fdtable, fd);
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(r);
    }

    ret = fd;

done:

    if (locals)
        free(locals);

    return ret;
}

/*
Given a dirfd and a pathname, return a concatenated absolute path.

Caveats:

- Sometimes abspath is set to equal to
  pathname, in which case no free is needed. The caller should check
  *abspath_out before free:
  e.g.
      if (*abspath_out != pathname)
          free(*abspath_out)

Arguments:
 - abspath_out: will point to the final concatenated absolute path.
    This method will allocate memory for abspath_out if necessary
    Caller should free the memory if abspath_out != pathname
 - flags_behavior: a bit mask that can be one or more of the following flags
FB_PATH_NOT_EMPTY: indicate pathname cannot be empty and type check on dirfd is
skipped
FB_TYPE_FILE: indicate file pointed by dirfd can be file
FB_TYPE_DIRECTORY: indicate file pointed by dirfd can be directory
FB_THROW_ERROR_NOFOLLOW: if set, throw ELOOP when abspath is a symlink
*/
long myst_get_absolute_path_from_dirfd(
    int dirfd,
    const char* pathname,
    int flags,
    char** abspath_out,
    const int flags_behavior)
{
    long ret = 0;
    myst_path_t* resolved_path = NULL;
    char* path_out = NULL;

    if (!pathname || !abspath_out)
        ERAISE(-EINVAL);

    // Absolute pathname or AT_FDCWD
    if (pathname[0] == '/' || dirfd == AT_FDCWD)
    {
        path_out = (char*)pathname;
    }
    // Empty pathname
    else if (pathname[0] == '\0')
    {
        if (!(flags & AT_EMPTY_PATH))
            ERAISE(-ENOENT);

        if (dirfd < 0)
            ERAISE(-EBADF);

        // Find realpath of dirfd
        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fdtable_type_t type;
        void* device = NULL;
        void* object = NULL;
        myst_fs_t* fs;
        myst_file_t* file;

        // first check dirfd is of file type, e.g. not tty
        ECHECK(myst_fdtable_get_any(fdtable, dirfd, &type, &device, &object));
        if (type != MYST_FDTABLE_TYPE_FILE)
            ERAISE(-ENOTDIR);

        // get the file object for the dirfd
        ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));

        // Check file type
        if (flags_behavior & (FB_TYPE_DIRECTORY | FB_TYPE_FILE))
        {
            struct stat buf;
            ERAISE((*fs->fs_fstat)(fs, file, &buf));

            // dirfd can be either file and directory in some cases, so:
            // Fail if dirfd is a directory, but shouldn't be
            if (!(flags_behavior & FB_TYPE_DIRECTORY) && S_ISDIR(buf.st_mode))
                ERAISE(-EACCES);

            // Fail if dirfd is a file, but shouldn't be
            if (!(flags_behavior & FB_TYPE_FILE) && !S_ISDIR(buf.st_mode))
                ERAISE(-ENOTDIR);
        }

        if (!(path_out = malloc(PATH_MAX)))
            ERAISE(-ENOMEM);
        // get the full path of dirfd
        ECHECK((*fs->fs_realpath)(fs, file, path_out, PATH_MAX));
    }
    // Relative pathname
    else
    {
        if (dirfd < 0)
            ERAISE(-EBADF);

        // Get abspath from dirfd
        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fdtable_type_t type;
        void* device = NULL;
        void* object = NULL;
        myst_fs_t* fs;
        myst_file_t* file;

        // first check dirfd is of file type, e.g. not tty
        ECHECK(myst_fdtable_get_any(fdtable, dirfd, &type, &device, &object));
        if (type != MYST_FDTABLE_TYPE_FILE)
            ERAISE(-ENOTDIR);

        // get the file object for the dirfd
        ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));

        // fail if not a directory
        {
            struct stat buf;
            ERAISE((*fs->fs_fstat)(fs, file, &buf));

            if (!S_ISDIR(buf.st_mode))
                ERAISE(-ENOTDIR);
        }

        if (!(path_out = malloc(PATH_MAX)))
            ERAISE(-ENOMEM);

        // get the full path of dirfd
        ECHECK((*fs->fs_realpath)(fs, file, path_out, PATH_MAX));

        // construct absolute path of file by concating path_out and pathname
        size_t dirname_len = strlen(path_out);
        size_t pathname_len = strlen(pathname);

        if (dirname_len + 1 + pathname_len >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        path_out[dirname_len] = '/';
        memcpy(path_out + dirname_len + 1, pathname, pathname_len + 1);
    }

    if (*path_out != '/')
    {
        if (!(resolved_path = (myst_path_t*)malloc(sizeof(myst_path_t))))
            ERAISE(-ENOMEM);

        // Construct absolute path
        ECHECK(myst_realpath(path_out, resolved_path));
    }

    *abspath_out = resolved_path ? resolved_path->buf : path_out;

    // Check symlink
    if ((flags_behavior & FB_THROW_ERROR_NOFOLLOW) &&
        (flags & AT_SYMLINK_NOFOLLOW))
    {
        struct stat statbuf;
        myst_syscall_lstat(*abspath_out, &statbuf);

        if (S_ISLNK(statbuf.st_mode))
            ERAISE(-ELOOP);
    }

done:
    if (*abspath_out != path_out && path_out != pathname)
        free(path_out);

    if (resolved_path && *abspath_out != resolved_path->buf)
        free(resolved_path);

    return ret;
}

static long _openat(
    int dirfd,
    const char* pathname,
    int flags,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    long ret = 0;
    char* abspath = NULL;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (file_out)
        *file_out = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_get_absolute_path_from_dirfd(
        dirfd, pathname, 0, &abspath, FB_PATH_NOT_EMPTY));

    if (fs_out && file_out)
    {
        myst_fs_t* fs;

        ECHECK(myst_mount_resolve(abspath, locals->suffix, &fs));
        ECHECK(
            (*fs->fs_open)(fs, locals->suffix, flags, mode, fs_out, file_out));
    }
    else
    {
        ret = myst_syscall_open(abspath, flags, mode);
    }

done:

    if (locals)
        free(locals);

    if (abspath != pathname)
        free(abspath);

    return ret;
}

long myst_syscall_openat(
    int dirfd,
    const char* pathname,
    int flags,
    mode_t mode)
{
    return _openat(dirfd, pathname, flags, mode, NULL, NULL);
}

long myst_syscall_epoll_create1(int flags)
{
    long ret = 0;
    myst_epolldev_t* ed = myst_epolldev_get();
    myst_epoll_t* epoll;
    int fd;

    if (!ed)
        ERAISE(-EINVAL);

    /* create the epoll object */
    ECHECK((*ed->ed_epoll_create1)(ed, flags, &epoll));

    /* add to file descriptor table */
    {
        myst_fdtable_t* fdtable = myst_fdtable_current();
        const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_EPOLL;

        if ((fd = myst_fdtable_assign(fdtable, fdtype, ed, epoll)) < 0)
        {
            (*ed->ed_close)(ed, epoll);
            ERAISE(fd);
        }
    }

    ret = fd;

done:

    return ret;
}

long myst_syscall_lseek(int fd, off_t offset, int whence)
{
    long ret = 0;
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    if (type == MYST_FDTABLE_TYPE_FILE)
    {
        myst_fs_t* fs = (myst_fs_t*)device;
        myst_file_t* file = (myst_file_t*)object;
        ret = ((*fs->fs_lseek)(fs, file, offset, whence));
    }
    else
    {
        /* Linux returns ESPIPE for non-seekable resources - pipes and sockets
         */
        ERAISE(-ESPIPE);
    }

done:
    return ret;
}

long myst_syscall_close(int fd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    if (type == MYST_FDTABLE_TYPE_FILE)
    {
        /* why does this sometimes fail? */
        myst_remove_fd_link(fd);
    }

    ECHECK(myst_fdtable_remove(fdtable, fd));
    ECHECK((*fdops->fd_close)(device, object));

done:
    return ret;
}

long myst_syscall_read(int fd, void* buf, size_t count)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_read)(device, object, buf, count);

done:
    return ret;
}

long myst_syscall_write(int fd, const void* buf, size_t count)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdops_t* fdops;

    if (!buf && count)
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    if (type == MYST_FDTABLE_TYPE_SOCK)
    {
        myst_sockdev_t* sockdev = (myst_sockdev_t*)fdops;
        ret = sockdev->sd_sendto(
            sockdev, object, buf, count, MSG_NOSIGNAL, NULL, 0);
        if (ret == -EPIPE)
            myst_signal_deliver(myst_thread_self(), SIGPIPE, NULL);
    }
    else
        ret = (*fdops->fd_write)(device, object, buf, count);

done:
    return ret;
}

long myst_syscall_pread(int fd, void* buf, size_t count, off_t offset)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;

    if (!buf && count)
        ERAISE(-EFAULT);

    if (offset < 0)
        ERAISE(-EINVAL);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    switch (type)
    {
        case MYST_FDTABLE_TYPE_FILE:
        {
            myst_fs_t* fs = device;
            myst_file_t* file = object;
            ret = (*fs->fs_pread)(fs, file, buf, count, offset);
            break;
        }
        case MYST_FDTABLE_TYPE_PIPE:
        {
            ret = -ESPIPE;
            break;
        }
        default:
        {
            ret = -ENOENT;
            break;
        }
    }

done:
    return ret;
}

long myst_syscall_pwrite(int fd, const void* buf, size_t count, off_t offset)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;

    if (!buf && count)
        ERAISE(-EFAULT);

    if (offset < 0)
        ERAISE(-EINVAL);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    switch (type)
    {
        case MYST_FDTABLE_TYPE_FILE:
        {
            myst_fs_t* fs = device;
            myst_file_t* file = object;
            ret = (*fs->fs_pwrite)(fs, file, buf, count, offset);
            break;
        }
        case MYST_FDTABLE_TYPE_PIPE:
        {
            ret = -ESPIPE;
            break;
        }
        default:
        {
            ret = -ENOENT;
            break;
        }
    }

done:
    return ret;
}

ssize_t myst_syscall_pwritev2(
    int fd,
    const struct iovec* iov,
    int iovcnt,
    off_t offset,
    int flags)
{
    ssize_t ret = 0;
    void* buf = NULL;
    ssize_t len;
    ssize_t nwritten;

    // ATTN: all flags are ignored since they are hints and have no
    // definitively perceptible effect.
    (void)flags;

    ECHECK(len = myst_iov_gather(iov, iovcnt, &buf));
    ECHECK(nwritten = myst_syscall_pwrite(fd, buf, len, offset));
    ret = nwritten;

done:

    if (buf)
        free(buf);

    return ret;
}

ssize_t myst_syscall_preadv2(
    int fd,
    const struct iovec* iov,
    int iovcnt,
    off_t offset,
    int flags)
{
    ssize_t ret = 0;
    ssize_t len;
    char buf[256];
    void* ptr = NULL;
    ssize_t nread;

    // ATTN: all flags are ignored since they are hints and have no
    // definitively perceptible effect.
    (void)flags;

    ECHECK(len = myst_iov_len(iov, iovcnt));

    if (len == 0)
        goto done;

    if (!(ptr = myst_buf_malloc(buf, sizeof(buf), len)))
        ERAISE(-ENOMEM);

    ECHECK(nread = myst_syscall_pread(fd, ptr, len, offset));
    ECHECK(myst_iov_scatter(iov, iovcnt, ptr, nread));
    ret = nread;

done:

    if (ptr)
        myst_buf_free(buf, ptr);

    return ret;
}

long myst_syscall_readv(int fd, const struct iovec* iov, int iovcnt)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdops_t* fdops;

    if (_iov_bad_addr(iov, iovcnt))
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_readv)(device, object, iov, iovcnt);

done:
    return ret;
}

long myst_syscall_writev(int fd, const struct iovec* iov, int iovcnt)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdops_t* fdops;

    if (_iov_bad_addr(iov, iovcnt))
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_writev)(device, object, iov, iovcnt);

done:
    return ret;
}

long myst_syscall_stat(const char* pathname, struct stat* statbuf)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_stat)(fs, locals->suffix, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_lstat(const char* pathname, struct stat* statbuf)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_lstat)(fs, locals->suffix, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_fstat(int fd, struct stat* statbuf)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device;
    void* object;
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_fstat)(device, object, statbuf);

done:
    return ret;
}

long myst_syscall_fstatat(
    int dirfd,
    const char* pathname,
    struct stat* statbuf,
    int flags)
{
    long ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
        char dirpath[PATH_MAX];
        char path[PATH_MAX];
    };
    struct locals* locals = NULL;

    if ((!pathname || *pathname == '\0') && !(flags & AT_EMPTY_PATH))
        ERAISE(-ENOENT);

    if (!statbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* If pathname is absolute, then ignore dirfd */
    if ((pathname && *pathname == '/') || dirfd == AT_FDCWD)
    {
        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            ECHECK(myst_syscall_lstat(pathname, statbuf));
            goto done;
        }
        else
        {
            ECHECK(myst_syscall_stat(pathname, statbuf));
            goto done;
        }
    }
    else if (!pathname || *pathname == '\0')
    {
        if (!(flags & AT_EMPTY_PATH))
            ERAISE(-EINVAL);

        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            myst_fdtable_t* fdtable = myst_fdtable_current();
            myst_fs_t* fs;
            myst_file_t* file;

            ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
            ECHECK((*fs->fs_realpath)(
                fs, file, locals->realpath, sizeof(locals->realpath)));
            ECHECK(myst_syscall_lstat(locals->realpath, statbuf));
            goto done;
        }
        else
        {
            ECHECK(myst_syscall_fstat(dirfd, statbuf));
            goto done;
        }
    }
    else
    {
        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fs_t* fs;
        myst_file_t* file;
        const char* finalpath;

        ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
        ECHECK((*fs->fs_realpath)(
            fs, file, locals->dirpath, sizeof(locals->dirpath)));

        if (pathname && (flags & AT_EMPTY_PATH))
        {
            finalpath = locals->dirpath;
        }
        else
        {
            ECHECK(myst_make_path(
                locals->path, sizeof(locals->path), locals->dirpath, pathname));
            finalpath = locals->path;
        }

        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            ECHECK(myst_syscall_lstat(finalpath, statbuf));
            goto done;
        }
        else
        {
            ECHECK(myst_syscall_stat(finalpath, statbuf));
            goto done;
        }
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static const char* _trim_trailing_slashes(
    const char* pathname,
    char* buf,
    size_t size)
{
    size_t len = strlen(pathname);

    if (len >= size)
        return NULL;

    /* if empty pathname or equal to "/" */
    if (len == 0 || (pathname[0] == '/' && pathname[1] == '\0'))
        return pathname;

    /* remove trailing slashes from the pathname if any */
    if (pathname[len - 1] == '/')
    {
        memcpy(buf, pathname, len + 1);

        for (char* p = buf + len; p != buf && p[-1] == '/'; *--p = '\0')
            ;

        pathname = buf;
    }

    return pathname;
}

long myst_syscall_mkdir(const char* pathname, mode_t mode)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
        char buf[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* remove trailing slash from directory name if any */
    if (!(pathname = _trim_trailing_slashes(
              pathname, locals->buf, sizeof(locals->buf))))
        ERAISE(-ENAMETOOLONG);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));

    ECHECK((*fs->fs_mkdir)(fs, locals->suffix, mode));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_mkdirat(int dirfd, const char* pathname, mode_t mode)
{
    char* abspath = NULL;
    long ret = 0;

    ECHECK(myst_get_absolute_path_from_dirfd(
        dirfd, pathname, 0, &abspath, FB_PATH_NOT_EMPTY));
    ECHECK(myst_syscall_mkdir(abspath, mode));

done:

    if (abspath != pathname)
        free(abspath);

    return ret;
}

long myst_syscall_rmdir(const char* pathname)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_rmdir)(fs, locals->suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_getdents64(int fd, struct dirent* dirp, size_t count)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t* file;
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get(fdtable, fd, type, (void**)&fs, (void**)&file));

    ret = (*fs->fs_getdents64)(fs, file, dirp, count);

done:
    return ret;
}

long myst_syscall_link(const char* oldpath, const char* newpath)
{
    return _myst_syscall_link_flags(oldpath, newpath, 0);
}

long _myst_syscall_link_flags(
    const char* oldpath,
    const char* newpath,
    int flags)
{
    long ret = 0;
    myst_fs_t* old_fs;
    myst_fs_t* new_fs;
    struct locals
    {
        char old_suffix[PATH_MAX];
        char new_suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(oldpath, locals->old_suffix, &old_fs));
    ECHECK(myst_mount_resolve(newpath, locals->new_suffix, &new_fs));

    if (old_fs != new_fs)
    {
        /* oldpath and newpath are not on the same mounted file system */
        ERAISE(-EXDEV);
    }

    ECHECK((*old_fs->fs_link)(
        old_fs, locals->old_suffix, locals->new_suffix, flags));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_linkat(
    int olddirfd,
    const char* oldpath,
    int newdirfd,
    const char* newpath,
    int flags)
{
    char* absoldpath = NULL;
    char* absnewpath = NULL;

    long ret = 0;

    if (flags & ~AT_SYMLINK_FOLLOW)
        ERAISE(-EINVAL);

    ECHECK(myst_get_absolute_path_from_dirfd(
        olddirfd, oldpath, 0, &absoldpath, FB_PATH_NOT_EMPTY));

    ECHECK(myst_get_absolute_path_from_dirfd(
        newdirfd, newpath, 0, &absnewpath, FB_PATH_NOT_EMPTY));

    ECHECK(_myst_syscall_link_flags(absoldpath, absnewpath, flags));

done:

    if (absoldpath != oldpath)
        free(absoldpath);

    if (absnewpath != newpath)
        free(absnewpath);

    return ret;
}

long myst_syscall_unlink(const char* pathname)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_unlink)(fs, locals->suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_unlinkat(int dirfd, const char* pathname, int flags)
{
    char* abspath = NULL;
    long ret = 0;

    (void)flags;

    if (flags & ~AT_REMOVEDIR)
        ERAISE(-EINVAL);

    ECHECK(myst_get_absolute_path_from_dirfd(
        dirfd, pathname, 0, &abspath, FB_PATH_NOT_EMPTY));

    if (flags & AT_REMOVEDIR)
    {
        ECHECK(myst_syscall_rmdir(abspath));
    }
    else
    {
        ECHECK(myst_syscall_unlink(abspath));
    }

done:

    if (abspath != pathname)
        free(abspath);

    return ret;
}

long myst_syscall_access(const char* pathname, int mode)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_access)(fs, locals->suffix, mode));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_faccessat(
    int dirfd,
    const char* pathname,
    int mode,
    int flags)
{
    long ret = 0;
    char* abspath = NULL;

    /* ATTN: support AT_ flags */
    (void)flags;

    ECHECK(myst_get_absolute_path_from_dirfd(
        dirfd, pathname, 0, &abspath, FB_PATH_NOT_EMPTY));
    ret = myst_syscall_access(abspath, mode);

done:

    if (abspath != pathname)
        free(abspath);

    return ret;
}

long myst_syscall_rename(const char* oldpath, const char* newpath)
{
    long ret = 0;
    myst_fs_t* old_fs;
    myst_fs_t* new_fs;
    struct locals
    {
        char old_suffix[PATH_MAX];
        char new_suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(oldpath, locals->old_suffix, &old_fs));
    ECHECK(myst_mount_resolve(newpath, locals->new_suffix, &new_fs));

    if (old_fs != new_fs)
    {
        /* oldpath and newpath are not on the same mounted file system */
        ERAISE(-EXDEV);
    }

    ECHECK(
        (*old_fs->fs_rename)(old_fs, locals->old_suffix, locals->new_suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_renameat(
    int olddirfd,
    const char* oldpath,
    int newdirfd,
    const char* newpath)
{
    long ret = 0;
    char* old_abspath = NULL;
    char* new_abspath = NULL;

    ECHECK(myst_get_absolute_path_from_dirfd(
        olddirfd, oldpath, 0, &old_abspath, FB_PATH_NOT_EMPTY));
    ECHECK(myst_get_absolute_path_from_dirfd(
        newdirfd, newpath, 0, &new_abspath, FB_PATH_NOT_EMPTY));
    ret = myst_syscall_rename(old_abspath, new_abspath);

done:

    if (old_abspath != oldpath)
        free(old_abspath);

    if (new_abspath != newpath)
        free(new_abspath);

    return ret;
}

long myst_syscall_truncate(const char* path, off_t length)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(path, locals->suffix, &fs));
    ERAISE((*fs->fs_truncate)(fs, locals->suffix, length));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_ftruncate(int fd, off_t length)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t* file;
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get(fdtable, fd, type, (void**)&fs, (void**)&file));
    ERAISE((*fs->fs_ftruncate)(fs, file, length));

done:
    return ret;
}

long myst_syscall_readlink(const char* pathname, char* buf, size_t bufsiz)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ERAISE((*fs->fs_readlink)(fs, locals->suffix, buf, bufsiz));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_readlinkat(
    int dirfd,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    long ret = 0;
    char* abspath = NULL;

    if (!buf || !bufsiz)
        ERAISE(-EINVAL);

    /*
     * ATTN: Since Linux 2.6.39, pathname can be an empty string, in which
     * case the call operates on the symbolic link referred to by dirfd.
     * But dirfd should have been obtained using open with the O_PATH
     * and O_NOFOLLOW flags. Our existing implementation of ext2_open()
     * dosn't support the O_PATH flag. If the trailing component
     * (i.e., basename) of pathname is a symbolic link, then the open
     * fails, with the error ELOOP.
     * Thus, return "No such file or directory"
     */
    ECHECK(myst_get_absolute_path_from_dirfd(
        dirfd, pathname, 0, &abspath, FB_PATH_NOT_EMPTY));
    ret = myst_syscall_readlink(abspath, buf, bufsiz);

done:

    if (abspath != pathname)
        free(abspath);

    return ret;
}

long myst_syscall_symlink(const char* target, const char* linkpath)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(linkpath, locals->suffix, &fs));
    ERAISE((*fs->fs_symlink)(fs, target, locals->suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_symlinkat(
    const char* target,
    int newdirfd,
    const char* linkpath)
{
    long ret = 0;
    char* abspath = NULL;

    ECHECK(myst_get_absolute_path_from_dirfd(
        newdirfd, linkpath, 0, &abspath, FB_PATH_NOT_EMPTY));
    ret = myst_syscall_symlink(target, abspath);

done:

    if (abspath != linkpath)
        free(abspath);

    return ret;
}

long myst_syscall_chdir(const char* path)
{
    long ret = 0;
    myst_process_t* process = myst_process_self();
    struct locals
    {
        char buf[PATH_MAX];
        char buf2[PATH_MAX];
    };
    struct locals* locals = NULL;
    bool locked = false;

    if (!path)
        ERAISE(-EINVAL);

    if (myst_is_bad_addr_read(path, sizeof(uint64_t)))
        ERAISE(-EFAULT);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* path may not be an empty string */
    if (*path == '\0')
        ERAISE(-ENOENT);

    myst_spin_lock(&process->cwd_lock);
    locked = true;

    /* filenames cannot be longer than NAME_MAX in Linux */
    if (strlen(myst_basename(path)) > NAME_MAX)
        ERAISE(-ENAMETOOLONG);

    ECHECK(myst_path_absolute_cwd(
        process->cwd, path, locals->buf, sizeof(locals->buf)));
    ECHECK(myst_normalize(locals->buf, locals->buf2, sizeof(locals->buf2)));

    /* fail if the directory does not exist */
    {
        struct stat buf;

        if (myst_syscall_stat(locals->buf2, &buf) != 0 || !S_ISDIR(buf.st_mode))
            ERAISE(-ENOENT);
    }

    char* tmp = strdup(locals->buf2);
    if (tmp == NULL)
        ERAISE(-ENOMEM);
    free(process->cwd);
    process->cwd = tmp;

done:

    if (locals)
        free(locals);

    if (locked)
        myst_spin_unlock(&process->cwd_lock);

    return ret;
}

long myst_syscall_fchdir(int fd)
{
    long ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
    }* locals = NULL;
    myst_process_t* process = myst_process_self();
    myst_file_t* file = NULL;
    myst_fs_t* fs = NULL;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    if (fd < 0)
        ERAISE(-EBADF);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));

    /* fail if the directory does not exist */
    {
        struct stat buf;

        if (fs->fs_fstat(fs, file, &buf) != 0 || !S_ISDIR(buf.st_mode))
            ERAISE(-ENOENT);
    }

    /* Get file path */
    ECHECK((*fs->fs_realpath)(
        fs, file, locals->realpath, sizeof(locals->realpath)));

    char* tmp = strdup(locals->realpath);
    if (tmp == NULL)
        ERAISE(-ENOMEM);

    myst_spin_lock(&process->cwd_lock);
    free(process->cwd);
    process->cwd = tmp;
    myst_spin_unlock(&process->cwd_lock);

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_getcwd(char* buf, size_t size)
{
    long ret = 0;
    myst_process_t* process = myst_process_self();

    myst_spin_lock(&process->cwd_lock);

    if (!buf)
        ERAISE(-EINVAL);

    if (myst_strlcpy(buf, process->cwd, size) >= size)
        ERAISE(-ERANGE);

    ret = (long)buf;

done:

    myst_spin_unlock(&process->cwd_lock);

    return ret;
}

long myst_syscall_statfs(const char* path, struct statfs* buf)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!path || !buf)
        ERAISE(-EINVAL);

    /* Reject empty path */
    if (*path == '\0')
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(path, locals->suffix, &fs));
    if (buf)
        memset(buf, 0, sizeof(*buf));
    ECHECK((*fs->fs_statfs)(fs, locals->suffix, buf));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_fstatfs(int fd, struct statfs* buf)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t* file;

    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get(fdtable, fd, type, (void**)&fs, (void**)&file));
    if (buf)
        memset(buf, 0, sizeof(*buf));
    ECHECK((*fs->fs_fstatfs)(fs, file, buf));

done:

    return ret;
}

static char _hostname[HOST_NAME_MAX] = "TEE";
static myst_spinlock_t _hostname_lock = MYST_SPINLOCK_INITIALIZER;

long myst_syscall_uname(struct utsname* buf)
{
    // We are emulating Linux syscalls. 5.4.0 is the LTS release we
    // try to emulate. The release number should be updated when
    // Mystikos adapts to syscall API changes in future Linux releases.
    MYST_STRLCPY(buf->sysname, "Linux");
    MYST_STRLCPY(buf->release, "5.4.0");
    MYST_STRLCPY(buf->version, "Mystikos 1.0.0");
    MYST_STRLCPY(buf->machine, "x86_64");

    myst_spin_lock(&_hostname_lock);
    MYST_STRLCPY(buf->nodename, _hostname);
    myst_spin_unlock(&_hostname_lock);

    return 0;
}

long myst_syscall_sethostname(const char* hostname, MYST_UNUSED size_t len)
{
    myst_spin_lock(&_hostname_lock);
    MYST_STRLCPY(_hostname, hostname);
    myst_spin_unlock(&_hostname_lock);

    return 0;
}

long myst_syscall_getrandom(void* buf, size_t buflen, unsigned int flags)
{
    long ret = 0;

    (void)flags;

    if (!buf && buflen)
        ERAISE(-EINVAL);

    if (buf && buflen && myst_tcall_random(buf, buflen) != 0)
        ERAISE(-EINVAL);

    ret = (long)buflen;

done:
    return ret;
}

long myst_syscall_fcntl(int fd, int cmd, long arg)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    if (cmd == F_DUPFD)
    {
        ret = myst_fdtable_dup(fdtable, MYST_DUPFD, fd, (int)arg, -1);
    }
    else if (cmd == F_DUPFD_CLOEXEC)
    {
        ret = myst_fdtable_dup(fdtable, MYST_DUPFD_CLOEXEC, fd, (int)arg, -1);
    }
    else
    {
        void* device = NULL;
        void* object = NULL;
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;

        ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
        fdops = device;
        ret = (*fdops->fd_fcntl)(device, object, cmd, arg);
    }

done:
    return ret;
}

long myst_syscall_chmod(const char* pathname, mode_t mode)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
        struct stat statbuf;
    }* locals = NULL;
    myst_thread_t* self = myst_thread_self();

    if (!pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));

    /* Root or owner of file can change mode */
    if (!self->euid == 0)
    {
        ECHECK(fs->fs_stat(fs, locals->suffix, &locals->statbuf));
        if (locals->statbuf.st_uid != self->euid)
            ERAISE(-EPERM);
    }
    ECHECK((*fs->fs_chmod)(fs, locals->suffix, mode));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_fchmod(int fd, mode_t mode)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    if (type == MYST_FDTABLE_TYPE_SOCK)
    {
        uid_t host_uid;
        gid_t host_gid;
        myst_fdops_t* fdops = device;
        int target_fd = (*fdops->fd_target_fd)(fdops, object);

        if (target_fd < 0)
            ERAISE(-EBADF);

        ECHECK(myst_enc_uid_to_host(myst_syscall_geteuid(), &host_uid));

        ECHECK(myst_enc_gid_to_host(myst_syscall_getegid(), &host_gid));

        long params[6] = {target_fd, mode, host_uid, host_gid};
        ret = _forward_syscall(SYS_fchmod, params);
    }
    else if (type == MYST_FDTABLE_TYPE_FILE)
    {
        myst_fs_t* fs = device;
        myst_thread_t* self = myst_thread_self();
        struct stat statbuf;

        /* Root or owner of file can change mode */
        if (!self->euid == 0)
        {
            ECHECK(fs->fs_fstat(fs, object, &statbuf));
            if (statbuf.st_uid != self->euid)
                ERAISE(-EPERM);
        }

        ECHECK((*fs->fs_fchmod)(fs, object, mode));
    }
    else
    {
        // The pipe type fd is unsupported. Calling chmod on pipe
        // is uncommon. To support pipe, pipedev needs to inherit
        // from the myst_fs interface.
        ERAISE(-ENOTSUP);
    }

done:
    return ret;
}

long myst_syscall_fchmodat(
    int dirfd,
    const char* pathname,
    mode_t mode,
    int flags)
{
    long ret = 0;
    char* abspath = NULL;

    // Man page states "AT_SYMLINK_NOFOLLOW is not supported".
    // MUSL C wrapper actually implemented this flag: the
    // wrapper digests this flag and will always pass flags=0
    // to syscall.
    if (flags & AT_SYMLINK_NOFOLLOW)
        ERAISE(-ENOTSUP);
    else if (flags)
        ERAISE(-EINVAL);

    ECHECK(myst_get_absolute_path_from_dirfd(
        dirfd, pathname, 0, &abspath, FB_PATH_NOT_EMPTY));
    ret = myst_syscall_chmod(abspath, mode);

done:

    if (abspath != pathname)
        free(abspath);

    return ret;
}

long myst_syscall_pipe2(int pipefd[2], int flags)
{
    int ret = 0;
    myst_pipe_t* pipe[2];
    int fd0;
    int fd1;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_PIPE;
    myst_pipedev_t* pd = myst_pipedev_get();
    static const ssize_t margin = 8;

    /* Linux raises EFAULT when pipefd is null */
    if (!pipefd)
        ERAISE(-EFAULT);

    /* Leave a little margin so pipe2() does not exhaust the last few fds */
    if (myst_fdtable_count(fdtable) < margin)
        ERAISE(-EMFILE);

    ECHECK((*pd->pd_pipe2)(pd, pipe, flags));

    if ((fd0 = myst_fdtable_assign(fdtable, type, pd, pipe[0])) < 0)
    {
        (*pd->pd_close)(pd, pipe[0]);
        (*pd->pd_close)(pd, pipe[1]);
        ERAISE(fd0);
    }

    if ((fd1 = myst_fdtable_assign(fdtable, type, pd, pipe[1])) < 0)
    {
        myst_fdtable_remove(fdtable, fd0);
        (*pd->pd_close)(pd, pipe[0]);
        (*pd->pd_close)(pd, pipe[1]);
        ERAISE(fd1);
    }

    pipefd[0] = fd0;
    pipefd[1] = fd1;

    if (_trace_syscall(SYS_pipe2))
        myst_eprintf("pipe2(): [%d:%d]\n", fd0, fd1);

done:
    return ret;
}

long myst_syscall_eventfd(unsigned int initval, int flags)
{
    long ret = 0;
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_EVENTFD;
    myst_eventfddev_t* dev = myst_eventfddev_get();
    myst_eventfd_t* obj = NULL;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    int fd;

    if (!dev)
        ERAISE(-EINVAL);

    ECHECK((*dev->eventfd)(dev, initval, flags, &obj));

    if ((fd = myst_fdtable_assign(fdtable, type, dev, obj)) < 0)
    {
        myst_fdtable_remove(fdtable, fd);
        (*dev->close)(dev, obj);
        ERAISE(fd);
    }

    ret = fd;

done:
    return ret;
}

long myst_syscall_inotify_init1(int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_INOTIFY;
    myst_inotifydev_t* dev = myst_inotifydev_get();
    myst_inotify_t* obj = NULL;
    int fd;

    ECHECK((*dev->id_inotify_init1)(dev, flags, &obj));

    if ((fd = myst_fdtable_assign(fdtable, type, dev, obj)) < 0)
    {
        (*dev->id_close)(dev, obj);
        ERAISE(fd);
    }

    ret = fd;

done:
    return ret;
}

long myst_syscall_inotify_add_watch(int fd, const char* pathname, uint32_t mask)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_inotifydev_t* dev;
    myst_inotify_t* obj;
    int wd;

    ECHECK(myst_fdtable_get_inotify(fdtable, fd, &dev, &obj));
    ECHECK(wd = (*dev->id_inotify_add_watch)(dev, obj, pathname, mask));
    ret = wd;

done:
    return ret;
}

long myst_syscall_inotify_rm_watch(int fd, int wd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_inotifydev_t* dev;
    myst_inotify_t* obj;

    ECHECK(myst_fdtable_get_inotify(fdtable, fd, &dev, &obj));
    ECHECK((*dev->id_inotify_rm_watch)(dev, obj, wd));

done:
    return ret;
}

static size_t _count_args(const char* const args[])
{
    size_t n = 0;

    if (args)
    {
        while (*args++)
            n++;
    }

    return n;
}

typedef struct syscall_args
{
    long n;
    long* params;
    myst_kstack_t* kstack;
    long user_rsp;
} syscall_args_t;

long myst_syscall_execveat(
    int dirfd,
    const char* pathname,
    char* const argv_in[],
    char* const envp[],
    int flags,
    myst_thread_t* const thread,
    syscall_args_t* const args)
{
    /* free the previous kernel stack from the SYS_execve syscall */
    if (thread->exec_kstack)
    {
        myst_put_kstack(thread->exec_kstack);
        thread->exec_kstack = NULL;
    }

    /* the kstack is freed later by next exec or by exit */
    thread->exec_kstack = args->kstack;

    long ret = 0;
    const char** argv = NULL;
    myst_thread_t* current_thread = myst_thread_self();
    char* abspath = NULL;

    ECHECK(myst_get_absolute_path_from_dirfd(
        dirfd,
        pathname,
        flags,
        &abspath,
        FB_THROW_ERROR_NOFOLLOW | FB_TYPE_FILE));

    /* Make a copy of argv_in[] and inject pathname into argv[0] */
    {
        size_t argc = _count_args((const char* const*)argv_in);

        if (!(argv = calloc(argc + 1, sizeof(char*))))
            ERAISE(-ENOMEM);

        for (size_t i = 0; i < argc; i++)
            argv[i] = argv_in[i];

        argv[0] = abspath;
        argv[argc] = NULL;
    }

    /* only returns on failure */
    if (myst_exec(
            current_thread,
            __myst_kernel_args.crt_data,
            __myst_kernel_args.crt_size,
            __myst_kernel_args.crt_reloc_data,
            __myst_kernel_args.crt_reloc_size,
            _count_args(argv),
            (const char**)argv,
            _count_args((const char* const*)envp),
            (const char**)envp,
            NULL, /* CRT args */
            0,    /* thread stack size */
            free,
            argv) != 0)
    {
        ECHECK(-ENOENT);
    }

done:
    if (abspath != pathname)
        free(abspath);

    if (argv)
        free(argv);

    /* myst_syscall_execveat() only returns on failure */
    /* when myst_syscall_execveat() returns on failure, kstack will be
     * freed by syscall framework. Set thread->exec_kstack to NULL to
     * avoid double free by the next SYS_execve syscall */
    thread->exec_kstack = NULL;
    return ret;
}

long myst_syscall_ioctl(int fd, unsigned long request, long arg)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_ioctl)(device, object, request, arg);

done:
    return ret;
}

int myst_syscall_bind(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_bind)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_connect(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;
    myst_fdtable_type_t type;

    ECHECK(myst_fdtable_get_any(
        fdtable, sockfd, &type, (void**)&sd, (void**)&sock));

    if (type != MYST_FDTABLE_TYPE_SOCK)
        ERAISE(-ENOTSOCK);

    if (myst_is_bad_addr_read(addr, sizeof(struct sockaddr)))
        ERAISE(-EFAULT);

    ret = (*sd->sd_connect)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_recvfrom(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    if (!buf && len)
        ERAISE(-EFAULT);

    if ((buf && myst_is_bad_addr_read_write(buf, len)) ||
        (src_addr &&
         myst_is_bad_addr_read_write(src_addr, sizeof(struct sockaddr))))
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_recvfrom)(sd, sock, buf, len, flags, src_addr, addrlen);

done:
    return ret;
}

long myst_syscall_sendto(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    if (!buf && len)
        ERAISE(-EFAULT);

    if ((int)addrlen < 0)
        ERAISE(-EINVAL);

    if (len >= UDP_PACKET_MAX_LENGTH)
        ERAISE(-EMSGSIZE);

    if ((buf && myst_is_bad_addr_read(buf, len)) ||
        (dest_addr &&
         myst_is_bad_addr_read(dest_addr, sizeof(struct sockaddr))))
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_sendto)(sd, sock, buf, len, flags, dest_addr, addrlen);

done:
    return ret;
}

long myst_syscall_setsid()
{
    long ret = -EPERM;
    myst_process_t* self = myst_process_self();

    /*
     * If the caller is already a group leader or part of a process group
     * whose leader is the caller's parent process,
     * a new session cannot be created.
     */
    if (self->pid == self->pgid || self->pgid == self->ppid)
        goto done;

    /*
     * The calling process is the leader of the new session and
     * the process group leader of the new process group. It
     * has no controlling terminal.
     */
    self->sid = self->pid;
    self->pgid = self->pid;
    ret = self->sid;

done:
    return ret;
}

long myst_syscall_socket(int domain, int type, int protocol)
{
    long ret = 0;
    myst_sockdev_t* sd;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sock_t* sock = NULL;
    int sockfd;
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_SOCK;

    ECHECK(myst_sockdev_resolve(domain, type, &sd));
    ECHECK((*sd->sd_socket)(sd, domain, type, protocol, &sock));

    if ((sockfd = myst_fdtable_assign(fdtable, fdtype, sd, sock)) < 0)
    {
        (*sd->sd_close)(sd, sock);
        ERAISE(sockfd);
    }

    ret = sockfd;

done:

    return ret;
}

long myst_syscall_accept4(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;
    myst_sock_t* new_sock = NULL;
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_SOCK;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ECHECK((*sd->sd_accept4)(sd, sock, addr, addrlen, flags, &new_sock));

    if ((sockfd = myst_fdtable_assign(fdtable, fdtype, sd, new_sock)) < 0)
    {
        (*sd->sd_close)(sd, new_sock);
        ERAISE(sockfd);
    }

    ret = sockfd;

done:

    return ret;
}

long myst_syscall_shutdown(int sockfd, int how)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_shutdown)(sd, sock, how);

done:
    return ret;
}

long myst_syscall_listen(int sockfd, int backlog)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_listen)(sd, sock, backlog);

done:
    return ret;
}

long myst_syscall_getsockname(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;
    myst_fdtable_type_t type;

    if (myst_is_bad_addr_read_write(addr, sizeof(struct sockaddr)) ||
        myst_is_bad_addr_read_write(addrlen, sizeof(socklen_t)))
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_any(
        fdtable, sockfd, &type, (void**)&sd, (void**)&sock));

    if (type != MYST_FDTABLE_TYPE_SOCK)
        ERAISE(-ENOTSOCK);

    ret = (*sd->sd_getsockname)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_socketpair(int domain, int type, int protocol, int sv[2])
{
    int ret = 0;
    int fd0;
    int fd1;
    myst_sock_t* pair[2];
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_SOCK;

    ECHECK(myst_sockdev_resolve(domain, type, &sd));
    ECHECK((*sd->sd_socketpair)(sd, domain, type, protocol, pair));

    if ((fd0 = myst_fdtable_assign(fdtable, fdtype, sd, pair[0])) < 0)
    {
        (*sd->sd_close)(sd, pair[0]);
        (*sd->sd_close)(sd, pair[1]);
        ERAISE(fd0);
    }

    if ((fd1 = myst_fdtable_assign(fdtable, fdtype, sd, pair[1])) < 0)
    {
        myst_fdtable_remove(fdtable, fd0);
        (*sd->sd_close)(sd, pair[0]);
        (*sd->sd_close)(sd, pair[1]);
        ERAISE(fd1);
    }

    sv[0] = fd0;
    sv[1] = fd1;

done:
    return ret;
}

long myst_syscall_getpeername(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_getpeername)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_setsockopt)(sd, sock, level, optname, optval, optlen);

done:
    return ret;
}

long myst_syscall_getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_getsockopt)(sd, sock, level, optname, optval, optlen);

done:
    return ret;
}

long myst_syscall_dup(int oldfd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_dup_type_t duptype = MYST_DUP;

    ret = myst_fdtable_dup(fdtable, duptype, oldfd, -1, -1);
    ECHECK(ret);

done:
    return ret;
}

long myst_syscall_dup2(int oldfd, int newfd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_dup_type_t duptype = MYST_DUP2;

    ret = myst_fdtable_dup(fdtable, duptype, oldfd, newfd, -1);
    ECHECK(ret);

done:
    return ret;
}

long myst_syscall_dup3(int oldfd, int newfd, int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_dup_type_t duptype = MYST_DUP3;

    ret = myst_fdtable_dup(fdtable, duptype, oldfd, newfd, flags);
    ECHECK(ret);

done:
    return ret;
}

long myst_syscall_sched_yield(void)
{
    long params[6] = {0};
    return myst_tcall(SYS_sched_yield, params);
}

long myst_syscall_nanosleep(const struct timespec* req, struct timespec* rem)
{
    long params[6] = {(long)req, (long)rem};
    return _forward_syscall(SYS_nanosleep, params);
}
#define NANO_IN_SECOND 1000000000

long myst_syscall_sysinfo(struct sysinfo* info)
{
    long ret = 0;
    long uptime_in_nsecs;
    size_t totalram;
    size_t freeram;

    if (!info)
        ERAISE(-EINVAL);

    ECHECK(myst_get_total_ram(&totalram));
    ECHECK(myst_get_free_ram(&freeram));

    // Only clear out non-reserved portion of the structure.
    // This is to be defensive against different sizes of this
    // structure in musl and glibc.
    memset(info, 0, sizeof(*info) - sizeof(info->__reserved));
    info->totalram = totalram;
    info->freeram = freeram;
    info->mem_unit = 1;

    ECHECK((info->procs = myst_get_num_threads()));

    ECHECK((uptime_in_nsecs = myst_times_uptime()));
    info->uptime = uptime_in_nsecs / NANO_IN_SECOND;

    // loads[3], sharedram, bufferram, totalswap,
    // freeswap, totalhigh and freehigh are not supported.

done:
    return ret;
}

long myst_syscall_epoll_ctl(int epfd, int op, int fd, struct epoll_event* event)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_epolldev_t* ed;
    myst_epoll_t* epoll;

    ECHECK(myst_fdtable_get_epoll(fdtable, epfd, &ed, &epoll));

    ret = (*ed->ed_epoll_ctl)(ed, epoll, op, fd, event);

done:
    return ret;
}

long myst_syscall_epoll_wait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_epolldev_t* ed;
    myst_epoll_t* epoll;

    if (epfd < 0)
        ERAISE(-EBADF);

    if (epfd == 0)
        ERAISE(-EINVAL);

    ECHECK(myst_fdtable_get_epoll(fdtable, epfd, &ed, &epoll));

    ret = (*ed->ed_epoll_wait)(ed, epoll, events, maxevents, timeout);

done:
    return ret;
}

long myst_syscall_getrusage(int who, struct rusage* usage)
{
    // ATTN: support per-thread usage reporting.
    if (who == RUSAGE_THREAD)
        return -EINVAL;

    struct tms tm;
    myst_times_process_times(myst_process_self(), &tm);

    long stime = tm.tms_stime;
    long utime = tm.tms_utime;

    if (who == RUSAGE_SELF)
    {
        stime = tm.tms_stime;
        utime = tm.tms_utime;
    }
    else if (who == RUSAGE_CHILDREN)
    {
        stime = tm.tms_cstime;
        utime = tm.tms_cutime;
    }

    // NOTE: glibc and musl have different sized rusage structures. Not clearing
    // out the reserved makes it inline with that of glibc.
    memset(usage, 0, sizeof(*usage) - sizeof(usage->__reserved));
    usage->ru_utime.tv_sec = utime / 1000000000;
    usage->ru_utime.tv_usec = utime % 1000000000 * 1000;
    usage->ru_stime.tv_sec = stime / 1000000000;
    usage->ru_stime.tv_usec = stime % 1000000000 * 1000;

    return 0;
}

long myst_syscall_fsync(int fd)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    if (fd < 0)
        ERAISE(-EBADF);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    if (type != MYST_FDTABLE_TYPE_FILE)
        ERAISE(-EROFS);

    ECHECK(((myst_fs_t*)device)->fs_fsync(device, (myst_file_t*)object));

done:
    return ret;
}

long myst_syscall_fdatasync(int fd)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    if (fd < 0)
        ERAISE(-EBADF);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    if (type != MYST_FDTABLE_TYPE_FILE)
        ERAISE(-EROFS);

    ECHECK(((myst_fs_t*)device)->fs_fdatasync(device, (myst_file_t*)object));

done:
    return ret;
}

long myst_syscall_sync(void)
{
    myst_fdtable_t* fdtable = myst_fdtable_current();
    return myst_fdtable_sync(fdtable);
}

long myst_syscall_utimensat(
    int dirfd,
    const char* pathname,
    const struct timespec times[2],
    int flags)
{
    long ret = 0;

    if (pathname == NULL)
    {
        myst_file_t* file = NULL;
        myst_fs_t* fs = NULL;
        myst_fdtable_t* fdtable = myst_fdtable_current();

        ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
        ECHECK((*fs->fs_futimens)(fs, file, times));
    }
    else
    {
        myst_fs_t* fs;
        myst_file_t* file;
        int oflags = (flags & ~AT_SYMLINK_NOFOLLOW);
        long r;

        /* translate AT_SYMLINK_NOFOLLOW to O_NOFOLLOW */
        if ((flags & AT_SYMLINK_NOFOLLOW))
            oflags |= O_NOFOLLOW;

        ECHECK(_openat(dirfd, pathname, oflags, O_RDONLY, &fs, &file));

        if ((r = (*fs->fs_futimens)(fs, file, times)) < 0)
        {
            (*fs->fs_close)(fs, file);
            ERAISE(r);
        }

        (*fs->fs_close)(fs, file);
    }

done:
    return ret;
}

long myst_syscall_futimesat(
    int dirfd,
    const char* pathname,
    const struct timeval times[2])
{
    long ret = 0;
    struct timespec buf[2];
    struct timespec* ts = NULL;

    if (times)
    {
        for (size_t i = 0; i < 2; i++)
        {
            const struct timeval* tv = &times[i];
            buf[i].tv_sec = tv->tv_sec + (tv->tv_usec / MICRO_IN_SECOND);
            buf[i].tv_nsec = (tv->tv_usec % MICRO_IN_SECOND) * 1000;
        }

        ts = buf;
    }

    ECHECK(myst_syscall_utimensat(dirfd, pathname, ts, 0));

done:
    return ret;
}

long myst_syscall_get_robust_list(
    int pid,
    myst_robust_list_head_t** head_ptr,
    size_t* len_ptr)
{
    long ret = 0;
    myst_thread_t* thread;

    if (pid < 0)
        ERAISE(-EINVAL);

    if (pid == 0)
        thread = myst_thread_self();
    else if (!(thread = myst_find_thread(pid)))
        ERAISE(-ESRCH);

    myst_spin_lock(&thread->robust_list_head_lock);
    {
        if (head_ptr)
            *head_ptr = thread->robust_list_head;

        if (len_ptr)
            *len_ptr = thread->robust_list_len;
    }
    myst_spin_unlock(&thread->robust_list_head_lock);

done:
    return ret;
}

long myst_syscall_set_robust_list(myst_robust_list_head_t* head, size_t len)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    if (len != sizeof(myst_robust_list_head_t))
        ERAISE(-EINVAL);

    myst_spin_lock(&thread->robust_list_head_lock);
    thread->robust_list_head = head;
    thread->robust_list_len = len;
    myst_spin_unlock(&thread->robust_list_head_lock);

done:
    return ret;
}

long myst_syscall_arch_prctl(int code, unsigned long* addr)
{
    long ret = 0;

    if (!addr)
        ERAISE(-EFAULT);

    if (code == ARCH_GET_FS)
    {
        *addr = (unsigned long)myst_get_fsbase();
    }
    else if (code == ARCH_GET_GS)
    {
        *addr = (unsigned long)myst_get_gsbase();
    }
    else if (code == ARCH_SET_FS)
    {
        struct myst_td* new = (struct myst_td*)addr;
        const struct myst_td* old = myst_get_fsbase();
        myst_set_fsbase((void*)new);
        new->canary = old->canary;
    }
    else if (code == ARCH_SET_GS)
    {
        ERAISE(-EINVAL);
    }
    else
    {
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

long myst_syscall_mbind(
    void* addr,
    unsigned long len,
    int mode,
    const unsigned long* nodemask,
    unsigned long maxnode,
    unsigned flags)
{
    long ret = 0;

    /* ATTN: stub implementation */

    (void)addr;
    (void)len;
    (void)mode;
    (void)nodemask;
    (void)maxnode;
    (void)flags;
    return ret;
}

long myst_syscall_get_process_thread_stack(void** stack, size_t* stack_size)
{
    long ret = 0;
    myst_process_t* self = myst_process_self();

    if (!stack || !stack_size || !self->exec_stack)
        ERAISE(-EINVAL);

    // can only be called from process thread
    if (!myst_is_process_thread(myst_thread_self()))
        ERAISE(-EINVAL);

    // exclude enclosing guard pages
    *stack = (uint8_t*)self->exec_stack + PAGE_SIZE;
    *stack_size = self->exec_stack_size - 2 * PAGE_SIZE;

done:
    return ret;
}

long myst_syscall_interrupt_thread(int tid)
{
    long ret = 0;
    myst_thread_t* thread;

    if (!(thread = myst_find_thread(tid)))
        ERAISE(-ESRCH);

    ECHECK(myst_interrupt_thread(thread));

done:
    return ret;
}

long myst_syscall_ret(long ret)
{
    if (ret < 0)
    {
        errno = (int)-ret;
        ret = -1;
    }

    return ret;
}

static const char* _fcntl_cmdstr(int cmd)
{
    switch (cmd)
    {
        case F_DUPFD:
            return "F_DUPFD";
        case F_SETFD:
            return "F_SETFD";
        case F_GETFD:
            return "F_GETFD";
        case F_SETFL:
            return "F_SETFL";
        case F_GETFL:
            return "F_GETFL";
        case F_SETOWN:
            return "F_SETOWN";
        case F_GETOWN:
            return "F_GETOWN";
        case F_SETSIG:
            return "F_SETSIG";
        case F_GETSIG:
            return "F_GETSIG";
        case F_SETLK:
            return "F_SETLK";
        case F_GETLK:
            return "F_GETLK";
        case F_SETLKW:
            return "F_SETLKW";
        case F_SETOWN_EX:
            return "F_SETOWN_EX";
        case F_GETOWN_EX:
            return "F_GETOWN_EX";
        case F_GETOWNER_UIDS:
            return "F_GETOWNER_UIDS";
        default:
            return "unknown";
    }
}

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE 128
#define FUTEX_CLOCK_REALTIME 256

static const char* _futex_op_str(int op)
{
    switch (op & ~FUTEX_PRIVATE)
    {
        case FUTEX_WAIT:
            return "FUTEX_WAIT";
        case FUTEX_WAKE:
            return "FUTEX_WAKE";
        case FUTEX_FD:
            return "FUTEX_FD";
        case FUTEX_REQUEUE:
            return "FUTEX_REQUEUE";
        case FUTEX_CMP_REQUEUE:
            return "FUTEX_CMP_REQUEUE";
        case FUTEX_WAKE_OP:
            return "FUTEX_WAKE_OP";
        case FUTEX_LOCK_PI:
            return "FUTEX_LOCK_PI";
        case FUTEX_UNLOCK_PI:
            return "FUTEX_UNLOCK_PI";
        case FUTEX_TRYLOCK_PI:
            return "FUTEX_TRYLOCK_PI";
        case FUTEX_WAIT_BITSET:
            return "FUTEX_WAIT_BITSET";
        default:
            return "UNKNOWN";
    }
}

static void _print_app_load_time(void)
{
    struct timespec now;
    static const char yellow[] = "\e[33m";
    static const char reset[] = "\e[0m";

    if (myst_syscall_clock_gettime(CLOCK_REALTIME, &now) == 0)
    {
        struct timespec start;
        start.tv_sec = __myst_boot_time.tv_sec;
        start.tv_nsec = __myst_boot_time.tv_nsec;

        long nsec = myst_lapsed_nsecs(&start, &now);
        __myst_boot_time = now;

        double secs = (double)nsec / (double)NANO_IN_SECOND;

        myst_eprintf("%s", yellow);
        myst_eprintf("kernel: app load time: %.4lf seconds", secs);
        myst_eprintf("%s\n", reset);
    }
}

void myst_dump_ramfs(void)
{
    myst_strarr_t paths = MYST_STRARR_INITIALIZER;

    if (myst_lsr("/", &paths, true) != 0)
        myst_panic("unexpected");

    for (size_t i = 0; i < paths.size; i++)
    {
        printf("%s\n", paths.data[i]);
    }

    myst_strarr_release(&paths);
}

static long _SYS_myst_trace(long n, long params[6])
{
    const char* msg = (const char*)params[0];

    _strace(n, "msg=%s", msg);

    return (_return(n, 0));
}

static long _SYS_myst_trace_ptr(long n, long params[6])
{
    printf(
        "trace: %s: %lx %ld\n", (const char*)params[0], params[1], params[1]);
    return (_return(n, 0));
}

static long _SYS_myst_dump_stack(long n, long params[6])
{
    const void* stack = (void*)params[0];

    _strace(n, NULL);

    myst_dump_stack((void*)stack);
    return (_return(n, 0));
}

static long _SYS_myst_dump_ehdr(long n, long params[6])
{
    myst_dump_ehdr((void*)params[0]);
    return (_return(n, 0));
}

static long _SYS_myst_dump_argv(long n, long params[6])
{
    int argc = (int)params[0];
    const char** argv = (const char**)params[1];

    printf("=== SYS_myst_dump_argv\n");

    printf("argc=%d\n", argc);
    printf("argv=%p\n", argv);

    for (int i = 0; i < argc; i++)
    {
        printf("argv[%d]=%s\n", i, argv[i]);
    }

    printf("argv[argc]=%p\n", argv[argc]);

    return (_return(n, 0));
}

static long _SYS_myst_add_symbol_file(long n, long params[6])
{
    const char* path = (const char*)params[0];
    const void* text = (const void*)params[1];
    size_t text_size = (size_t)params[2];
    long ret = 0;

    _strace(n, "path=\"%s\" text=%p text_size=%zu", path, text, text_size);

    if (__myst_kernel_args.debug_symbols)
        ret = myst_syscall_add_symbol_file(path, text, text_size);

    return (_return(n, ret));
}

static long _SYS_myst_load_symbols(long n, long params[6])
{
    long ret = 0;

    (void)params;

    _strace(n, NULL);

    if (__myst_kernel_args.debug_symbols)
        ret = myst_syscall_load_symbols();

    return (_return(n, ret));
}

static long _SYS_myst_unload_symbols(long n, long params[6])
{
    long ret = 0;

    (void)params;

    _strace(n, NULL);

    if (__myst_kernel_args.debug_symbols)
        ret = myst_syscall_unload_symbols();

    return (_return(n, ret));
}

static long _SYS_myst_gen_creds(long n, long params[6])
{
    _strace(n, NULL);
    return (_forward_syscall(MYST_TCALL_GEN_CREDS, params));
}

static long _SYS_myst_free_creds(long n, long params[6])
{
    _strace(n, NULL);
    return (_forward_syscall(MYST_TCALL_FREE_CREDS, params));
}

static long _SYS_myst_gen_creds_ex(long n, long params[6])
{
    _strace(n, NULL);
    return (_forward_syscall(MYST_TCALL_GEN_CREDS_EX, params));
}

static long _SYS_myst_verify_cert(long n, long params[6])
{
    _strace(n, NULL);
    return (_forward_syscall(MYST_TCALL_VERIFY_CERT, params));
}

static long _SYS_myst_max_threads(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, __myst_kernel_args.max_threads));
}

static long _SYS_myst_poll_wake(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_tcall_poll_wake()));
}

#ifdef MYST_ENABLE_GCOV

static long _SYS_myst_gcov(long n, long params[6])
{
    const char* func = (const char*)params[0];
    long* gcov_params = (long*)params[1];

    _strace(n, "func=%s gcov_params=%p", func, gcov_params);

    long ret = myst_gcov(func, gcov_params);
    return (_return(n, ret));
}
#endif

static long _SYS_myst_unmap_on_exit(
    long n,
    long params[6],
    myst_thread_t* thread)
{
    void* ptr = (void*)params[0];
    size_t size = (size_t)params[1];

    _strace(n, "ptr=%p, size=%zu", ptr, size);

    return (_return(n, myst_syscall_unmap_on_exit(thread, ptr, size)));
}

static long _SYS_myst_get_exec_stack_option(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, __myst_kernel_args.exec_stack));
}

static long _SYS_myst_get_process_thread_stack(long n, long params[6])
{
    _strace(n, NULL);
    void** stack = (void**)params[0];
    size_t* stack_size = (size_t*)params[1];

    _strace(n, "stack=%p stack_size=%p", stack, stack_size);

    long ret = myst_syscall_get_process_thread_stack(stack, stack_size);
    return (_return(n, ret));
}

static long _SYS_read(long n, long params[6])
{
    int fd = (int)params[0];
    void* buf = (void*)params[1];
    size_t count = (size_t)params[2];

    _strace(n, "fd=%d buf=%p count=%zu", fd, buf, count);

    return (_return(n, myst_syscall_read(fd, buf, count)));
}

static long _SYS_write(long n, long params[6])
{
    int fd = (int)params[0];
    const void* buf = (const void*)params[1];
    size_t count = (size_t)params[2];
    long ret;

    _strace(n, "fd=%d buf=%p count=%zu", fd, buf, count);

    if (!buf && count)
        ret = -EINVAL;
    else if (buf && myst_is_bad_addr_read(buf, count))
        ret = -EFAULT;
    else
        ret = myst_syscall_write(fd, buf, count);
    return (_return(n, ret));
}

static long _SYS_pread64(long n, long params[6])
{
    int fd = (int)params[0];
    void* buf = (void*)params[1];
    size_t count = (size_t)params[2];
    off_t offset = (off_t)params[3];

    _strace(n, "fd=%d buf=%p count=%zu offset=%ld", fd, buf, count, offset);

    return (_return(n, myst_syscall_pread(fd, buf, count, offset)));
}

static long _SYS_pwrite64(long n, long params[6])
{
    int fd = (int)params[0];
    void* buf = (void*)params[1];
    size_t count = (size_t)params[2];
    off_t offset = (off_t)params[3];

    _strace(n, "fd=%d buf=%p count=%zu offset=%ld", fd, buf, count, offset);

    return (_return(n, myst_syscall_pwrite(fd, buf, count, offset)));
}

static long _SYS_open(long n, long params[6])
{
    const char* path = (const char*)params[0];
    int flags = (int)params[1];
    mode_t mode = (mode_t)params[2];
    myst_process_t* process = myst_process_self();
    long ret;

    _strace(
        n,
        "path=\"%s\" flags=0%o mode=0%o umask=0%o",
        path,
        flags,
        mode,
        process->umask);

    /* Apply umask */
    /* ATTN: Implementaiton need to be updated if directory ACL is
     * supported */
    mode = mode & (~(process->umask));

    ret = myst_syscall_open(path, flags, mode);

    return (_return(n, ret));
}

static long _SYS_close(long n, long params[6])
{
    int fd = (int)params[0];

    _strace(n, "fd=%d", fd);

    return (_return(n, myst_syscall_close(fd)));
}

static long _SYS_stat(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    struct stat* statbuf = (struct stat*)params[1];

    _strace(n, "pathname=\"%s\" statbuf=%p", pathname, statbuf);

    return (_return(n, myst_syscall_stat(pathname, statbuf)));
}

static long _SYS_fstat(long n, long params[6])
{
    int fd = (int)params[0];
    void* statbuf = (void*)params[1];

    _strace(n, "fd=%d statbuf=%p", fd, statbuf);

    return (_return(n, myst_syscall_fstat(fd, statbuf)));
}

static long _SYS_lstat(long n, long params[6])
{
    /* ATTN: remove this! */
    const char* pathname = (const char*)params[0];
    struct stat* statbuf = (struct stat*)params[1];

    _strace(n, "pathname=\"%s\" statbuf=%p", pathname, statbuf);

    return (_return(n, myst_syscall_lstat(pathname, statbuf)));
}

static long _SYS_poll(long n, long params[6])
{
    struct pollfd* fds = (struct pollfd*)params[0];
    nfds_t nfds = (nfds_t)params[1];
    int timeout = (int)params[2];
    long ret;

    _strace(n, "fds=%p nfds=%ld timeout=%d", fds, nfds, timeout);

    if (_trace_syscall(SYS_poll))
    {
        for (nfds_t i = 0; i < nfds; i++)
            myst_eprintf("fd=%d\n", fds[i].fd);
    }

    ret = myst_syscall_poll(fds, nfds, timeout, false);
    return (_return(n, ret));
}

static long _SYS_lseek(long n, long params[6])
{
    int fd = (int)params[0];
    off_t offset = (off_t)params[1];
    int whence = (int)params[2];

    _strace(n, "fd=%d offset=%ld whence=%d", fd, offset, whence);

    return (_return(n, myst_syscall_lseek(fd, offset, whence)));
}

static long _SYS_mmap(long n, long params[6], const myst_process_t* process)
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];
    int prot = (int)params[2];
    int flags = (int)params[3];
    int fd = (int)params[4];
    off_t offset = (off_t)params[5];

    _strace(
        n,
        "addr=%lx length=%zu(%lx) prot=%d flags=%d fd=%d offset=%lu",
        (long)addr,
        length,
        length,
        prot,
        flags,
        fd,
        offset);

    if (process->is_pseudo_fork_process &&
        __myst_kernel_args.fork_mode == myst_fork_pseudo_wait_for_exit_exec)
        myst_panic("mmap unsupported: pseudo fork process is calling "
                   "mmap when running in pseudo_wait mode");

    if ((uintptr_t)addr % PAGE_SIZE || !length)
        return (_return(n, -EINVAL));

    /* mman supports non-null addr if - existing mapping, MAP_FIXED
     * passed in flags and process must own the existing mapping. */
    if (addr && length)
    {
        if (flags & MAP_FIXED)
        {
            pid_t pid = myst_getpid();

            size_t rounded_up_length;
            if (myst_round_up(length, PAGE_SIZE, &rounded_up_length) < 0)
                return (_return(n, -EINVAL));

            /* if calling process does not own this mapping */
            if (myst_mman_pids_test(addr, rounded_up_length, pid) !=
                (ssize_t)rounded_up_length)
                return (_return(n, -EINVAL));
        }
        else
        {
            /* address hint is unsupported */
            addr = NULL;
        }
    }

    /* this can return (void*)-errno */
    long ret = (long)myst_mmap(addr, length, prot, flags, fd, offset);

    // ATTN : temporary workaround for myst_mmap()  inaccurate return
    // value issue
    if (ret == -1 || !ret)
    {
        ret = -ENOMEM;
    }
    else if (ret > 0)
    {
        pid_t pid = myst_getpid();
        void* ptr = (void*)ret;

        /* set ownership this mapping to pid */
        if (myst_mman_pids_set(ptr, length, pid) != 0)
            myst_panic("myst_mman_pids_set()");

        ret = (long)ptr;
    }

    return (_return(n, ret));
}

static long _SYS_mprotect(long n, long params[6])
{
    const void* addr = (void*)params[0];
    const size_t length = (size_t)params[1];
    const int prot = (int)params[2];

    _strace(
        n,
        "addr=%lx length=%zu(%lx) prot=%d",
        (long)addr,
        length,
        length,
        prot);

    return (_return(n, (long)myst_mprotect(addr, length, prot)));
}

static long _SYS_munmap(
    long n,
    long params[6],
    myst_thread_t* thread,
    const myst_td_t* crt_td)
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];

    _strace(n, "addr=%lx length=%zu(%lx)", (long)addr, length, length);

    // if the ummapped region overlaps the CRT thread descriptor, then
    // postpone the unmap because unmapping now would invalidate the
    // stack canary and would raise __stack_chk_fail(); this occurs
    // when munmap() is called from __unmapself()
    if (crt_td && addr && length)
    {
        const uint8_t* p = (const uint8_t*)crt_td;
        const uint8_t* pend = p + sizeof(myst_td_t);
        const uint8_t* q = (const uint8_t*)addr;
        const uint8_t* qend = q + length;

        if ((p >= q && p < qend) || (pend >= q && pend < qend))
        {
            /* unmap this later when the thread exits */
            return (
                _return(n, myst_syscall_unmap_on_exit(thread, addr, length)));
        }
    }

    long ret = (long)myst_munmap(addr, length);

    if (ret == 0)
    {
        /* set ownership this mapping to nobody */
        if (myst_mman_pids_set(addr, length, 0) != 0)
            myst_panic("myst_mman_pids_set()");
    }

    return (_return(n, ret));
}

static long _SYS_brk(long n, long params[6])
{
    void* addr = (void*)params[0];
    long ret;

    _strace(n, "addr=%lx", (long)addr);

    if (__myst_kernel_args.nobrk)
        ret = -ENOTSUP;
    else
        ret = myst_syscall_brk(addr);

    return (_return(n, ret));
}

static long _SYS_rt_sigaction(long n, long params[6])
{
    int signum = (int)params[0];
    const posix_sigaction_t* act = (const posix_sigaction_t*)params[1];
    posix_sigaction_t* oldact = (posix_sigaction_t*)params[2];

    _strace(
        n,
        "signum=%d(%s) act=%p oldact=%p",
        signum,
        myst_signum_to_string(signum),
        act,
        oldact);

    long ret = myst_signal_sigaction(signum, act, oldact);
    return (_return(n, ret));
}

static long _SYS_rt_sigprocmask(long n, long params[6])
{
    int how = (int)params[0];
    const sigset_t* set = (sigset_t*)params[1];
    sigset_t* oldset = (sigset_t*)params[2];

    _strace(n, "how=%d set=%p oldset=%p", how, set, oldset);

    long ret = myst_signal_sigprocmask(how, set, oldset);
    return (_return(n, ret));
}

static long _SYS_ioctl(long n, long params[6])
{
    int fd = (int)params[0];
    unsigned long request = (unsigned long)params[1];
    long arg = (long)params[2];
    int iarg = -1;

    if (request == FIONBIO && arg)
        iarg = *(int*)arg;

    _strace(n, "fd=%d request=0x%lx arg=%lx iarg=%d", fd, request, arg, iarg);

    return (_return(n, myst_syscall_ioctl(fd, request, arg)));
}

static long _SYS_readv(long n, long params[6])
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];

    _strace(n, "fd=%d iov=%p iovcnt=%d", fd, iov, iovcnt);

    return (_return(n, myst_syscall_readv(fd, iov, iovcnt)));
}

static long _SYS_writev(long n, long params[6])
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];

    _strace(n, "fd=%d iov=%p iovcnt=%d", fd, iov, iovcnt);

    return (_return(n, myst_syscall_writev(fd, iov, iovcnt)));
}

static long _SYS_access(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    int mode = (int)params[1];

    _strace(n, "pathname=\"%s\" mode=%d", pathname, mode);

    return (_return(n, myst_syscall_access(pathname, mode)));
}

static long _SYS_pipe(long n, long params[6])
{
    int* pipefd = (int*)params[0];

    _strace(n, "pipefd=%p flags=%0o", pipefd, 0);

    return (_return(n, myst_syscall_pipe2(pipefd, 0)));
}

static long _SYS_select(long n, long params[6])
{
    int nfds = (int)params[0];
    fd_set* rfds = (fd_set*)params[1];
    fd_set* wfds = (fd_set*)params[2];
    fd_set* efds = (fd_set*)params[3];
    struct timeval* timeout = (struct timeval*)params[4];
    long ret;

    if (_trace_syscall(SYS_select))
    {
        struct timeval* _timeout = timeout;
        if (timeout &&
            myst_is_bad_addr_read_write(timeout, sizeof(struct timeval)))
        {
            _timeout = NULL;
        }

        _strace(
            n,
            "nfds=%d rfds=%p wfds=%p xfds=%p timeout=%p(sec=%ld, "
            "usec=%ld)",
            nfds,
            rfds,
            wfds,
            efds,
            timeout,
            _timeout ? timeout->tv_sec : 0,
            _timeout ? timeout->tv_usec : 0);
    }

    ret = myst_syscall_select(nfds, rfds, wfds, efds, timeout);
    return (_return(n, ret));
}

static long _SYS_sched_yield(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);

    return (_return(n, myst_syscall_sched_yield()));
}

static long _SYS_mremap(long n, long params[6])
{
    void* old_address = (void*)params[0];
    size_t old_size = (size_t)params[1];
    size_t new_size = (size_t)params[2];
    int flags = (int)params[3];
    void* new_address = (void*)params[4];
    long ret;

    _strace(
        n,
        "old_address=%p "
        "old_size=%zu "
        "new_size=%zu "
        "flags=%d "
        "new_address=%p ",
        old_address,
        old_size,
        new_size,
        flags,
        new_address);

    {
        const pid_t pid = myst_getpid();
        myst_assume(pid > 0);

        /* fail if the calling process does not own this mapping */
        if (myst_mman_pids_test(old_address, old_size, pid) !=
            (ssize_t)old_size)
            return (_return(n, -EINVAL));
    }

    ret =
        (long)myst_mremap(old_address, old_size, new_size, flags, new_address);

    if (ret >= 0)
    {
        const pid_t pid = myst_getpid();

        /* set ownership of old mapping to nobody */
        if (myst_mman_pids_set(old_address, old_size, 0) != 0)
            myst_panic("myst_mman_pids_set()");

        /* set ownership of new mapping to pid */
        if (myst_mman_pids_set((const void*)ret, new_size, pid) != 0)
            myst_panic("myst_mman_pids_set()");
    }

    return (_return(n, ret));
}

static long _SYS_msync(long n, long params[6])
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];
    int flags = (int)params[2];

    _strace(n, "addr=%p length=%zu flags=%d ", addr, length, flags);

    return (_return(n, myst_msync(addr, length, flags)));
}

static long _SYS_madvise(long n, long params[6])
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];
    int advice = (int)params[2];

    _strace(n, "addr=%p length=%zu advice=%d", addr, length, advice);

    return (_return(n, 0));
}

static long _SYS_dup(long n, long params[6])
{
    int oldfd = (int)params[0];
    long ret;

    _strace(n, "oldfd=%d", oldfd);

    ret = myst_syscall_dup(oldfd);
    return (_return(n, ret));
}

static long _SYS_dup2(long n, long params[6])
{
    int oldfd = (int)params[0];
    int newfd = (int)params[1];
    long ret;

    _strace(n, "oldfd=%d newfd=%d", oldfd, newfd);

    ret = myst_syscall_dup2(oldfd, newfd);
    return (_return(n, ret));
}

static long _SYS_dup3(long n, long params[6])
{
    int oldfd = (int)params[0];
    int newfd = (int)params[1];
    int flags = (int)params[2];
    long ret;

    _strace(n, "oldfd=%d newfd=%d flags=%o", oldfd, newfd, flags);

    ret = myst_syscall_dup3(oldfd, newfd, flags);
    return (_return(n, ret));
}

static long _SYS_pause(long n, long params[6])
{
    long ret;

    (void)params;

    _strace(n, NULL);
    ret = myst_syscall_pause();
    return (_return(n, ret));
}

static long _SYS_nanosleep(long n, long params[6])
{
    const struct timespec* req = (const struct timespec*)params[0];
    struct timespec* rem = (struct timespec*)params[1];
    struct timespec_buf buf;

    _strace(n, "req=%s rem=%p", _format_timespec(&buf, req), rem);

    return (_return(n, myst_syscall_nanosleep(req, rem)));
}

static long _SYS_myst_run_itimer(
    long n,
    long params[6],
    myst_process_t* process)
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_syscall_run_itimer(process)));
}

static long _SYS_myst_start_shell(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);

    if (__myst_kernel_args.shell_mode)
        myst_start_shell("\nMystikos shell (syscall)\n");

    return (_return(n, 0));
}

static long _SYS_getitimer(long n, long params[6], myst_process_t* process)
{
    int which = (int)params[0];
    struct itimerval* curr_value = (void*)params[1];

    _strace(n, "which=%d curr_value=%p", which, curr_value);

    return (_return(n, myst_syscall_getitimer(process, which, curr_value)));
}

static long _SYS_setitimer(long n, long params[6], myst_process_t* process)
{
    int which = (int)params[0];
    const struct itimerval* new_value = (void*)params[1];
    struct itimerval* old_value = (void*)params[2];

    _strace(
        n,
        "which=%d new_value=%p(interval {sec=%ld usec=%ld} value "
        "{sec=%ld usec=%ld}) old_value=%p",
        which,
        new_value,
        new_value ? new_value->it_interval.tv_sec : 0,
        new_value ? new_value->it_interval.tv_usec : 0,
        new_value ? new_value->it_value.tv_sec : 0,
        new_value ? new_value->it_value.tv_usec : 0,
        old_value);

    return (_return(
        n, myst_syscall_setitimer(process, which, new_value, old_value)));
}

static long _SYS_getpid(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);

    return (_return(n, myst_getpid()));
}

static long _SYS_myst_clone(long n, long params[6])
{
    long* args = (long*)params[0];
    int (*fn)(void*) = (void*)args[0];
    void* child_stack = (void*)args[1];
    int flags = (int)args[2];
    void* arg = (void*)args[3];
    pid_t* ptid = (pid_t*)args[4];
    void* newtls = (void*)args[5];
    pid_t* ctid = (void*)args[6];

    _strace(
        n,
        "fn=%p "
        "child_stack=%p "
        "flags=%x "
        "arg=%p "
        "ptid=%p "
        "newtls=%p "
        "ctid=%p",
        fn,
        child_stack,
        flags,
        arg,
        ptid,
        newtls,
        ctid);

    long ret =
        myst_syscall_clone(fn, child_stack, flags, arg, ptid, newtls, ctid);

    return _return(n, ret);
}

static long _SYS_myst_get_fork_info(
    long n,
    long params[6],
    myst_process_t* process)
{
    myst_fork_info_t* arg = (myst_fork_info_t*)params[0];

    _strace(n, NULL);

    long ret = myst_syscall_get_fork_info(process, arg);
    return (_return(n, ret));
}

static long _SYS_myst_interrupt_thread(long n, long params[6])
{
    int tid = (int)params[0];

    _strace(n, "tid=%d\n", tid);

    long ret = myst_syscall_interrupt_thread(tid);
    return (_return(n, ret));
}

static long _SYS_myst_fork_wait_exec_exit(
    long n,
    long params[6],
    myst_thread_t* thread)
{
    int ret = 0;

    (void)params;

    _strace(n, NULL);
    myst_futex_wait(
        &thread->fork_exec_futex_wait, 0, NULL, FUTEX_BITSET_MATCH_ANY);
    return (_return(n, ret));
}

static long _SYS_myst_kill_wait_child_forks(
    long n,
    long params[6],
    myst_process_t* process)
{
    long ret = 0;

    (void)params;

    _strace(n, NULL);

    kill_child_fork_processes(process);

    if (process->is_parent_of_pseudo_fork_process)
    {
        while (myst_have_child_forked_processes(process))
        {
            /* ATTN: revisit whether signals should be processed */
            myst_sleep_msec(10, false);
        }
    }
    return (_return(n, ret));
}

static long _SYS_execve(
    long n,
    long params[6],
    myst_thread_t* thread,
    syscall_args_t* args)
{
    const char* filename = (const char*)params[0];
    char** argv = (char**)params[1];
    char** envp = (char**)params[2];

    _strace(n, "filename=%s argv=%p envp=%p", filename, argv, envp);

    long ret =
        myst_syscall_execveat(AT_FDCWD, filename, argv, envp, 0, thread, args);

    return _return(n, ret);
}

static long _SYS_exit_group(
    long n,
    long params[6],
    syscall_args_t* args,
    myst_thread_t* thread,
    myst_process_t* process)
{
    const int status = (int)params[0];

    _strace(n, "status=%d", status);

    /* uncomment to print out free space on process exit */
#if 0
            {
                size_t size;
                myst_get_free_ram(&size);
                myst_eprintf(
                    "=== exit: free ram: %5.3lfm\n", (double)size / 1048576.0);
            }
#endif

    if (!thread || thread->magic != MYST_THREAD_MAGIC)
        myst_panic("unexpected");

    if (((n == SYS_exit) && (thread->group_next == NULL) &&
         (thread->group_prev == NULL)) ||
        (n == SYS_exit_group))
    {
        bool process_status_set = false;
        if (__atomic_compare_exchange_n(
                &process->exit_status_signum_set,
                &process_status_set,
                true,
                false,
                __ATOMIC_RELEASE,
                __ATOMIC_ACQUIRE))
        {
            process->exit_status = status;
            process->terminating_signum = 0;
        }
    }

    if (n == SYS_exit_group)
        myst_kill_thread_group();

    /* the kstack is freed after the long-jump below */
    thread->exit_kstack = args->kstack;

    /* jump back to myst_enter_kernel() */
    myst_longjmp(&thread->jmpbuf, 1);

    /* unreachable */
    return 0;
}

static long _SYS_wait4(long n, long params[6])
{
    pid_t pid = (pid_t)params[0];
    int* wstatus = (int*)params[1];
    int options = (int)params[2];
    struct rusage* rusage = (struct rusage*)params[3];
    long ret;

    _strace(
        n,
        "pid=%d wstatus=%p options=%d rusage=%p",
        pid,
        wstatus,
        options,
        rusage);
    ret = myst_syscall_wait4(pid, wstatus, options, rusage);
    return (_return(n, ret));
}

static long _SYS_kill(long n, long params[6])
{
    int pid = (int)params[0];
    int sig = (int)params[1];

    _strace(n, "pid=%d sig=%d(%s)", pid, sig, myst_signum_to_string(sig));

    long ret = myst_syscall_kill(pid, sig);
    return (_return(n, ret));
}

static long _SYS_uname(long n, long params[6])
{
    struct utsname* buf = (struct utsname*)params[0];

    return (_return(n, myst_syscall_uname(buf)));
}

static long _SYS_fcntl(long n, long params[6])
{
    int fd = (int)params[0];
    int cmd = (int)params[1];
    long arg = (long)params[2];
    long ret;

    const char* cmdstr = _fcntl_cmdstr(cmd);
    _strace(n, "fd=%d cmd=%d(%s) arg=0%lo", fd, cmd, cmdstr, arg);

    ret = myst_syscall_fcntl(fd, cmd, arg);
    return (_return(n, ret));
}

static long _SYS_flock(long n, long params[6])
{
    int fd = (int)params[0];
    int cmd = (int)params[1];

    _strace(n, "fd=%d cmd=%d", fd, cmd);

    return (_return(n, 0));
}

static long _SYS_fsync(long n, long params[6])
{
    int fd = (int)params[0];

    _strace(n, "fd=%d", fd);

    return (_return(n, myst_syscall_fsync(fd)));
}

static long _SYS_fdatasync(long n, long params[6])
{
    int fd = (int)params[0];

    _strace(n, "fd=%d", fd);

    return (_return(n, myst_syscall_fdatasync(fd)));
}

static long _SYS_truncate(long n, long params[6])
{
    const char* path = (const char*)params[0];
    off_t length = (off_t)params[1];

    _strace(n, "path=\"%s\" length=%ld", path, length);

    return (_return(n, myst_syscall_truncate(path, length)));
}

static long _SYS_ftruncate(long n, long params[6])
{
    int fd = (int)params[0];
    off_t length = (off_t)params[1];

    _strace(n, "fd=%d length=%ld", fd, length);

    return (_return(n, myst_syscall_ftruncate(fd, length)));
}

static long _SYS_getcwd(long n, long params[6])
{
    char* buf = (char*)params[0];
    size_t size = (size_t)params[1];

    _strace(n, "buf=%p size=%zu", buf, size);

    return (_return(n, myst_syscall_getcwd(buf, size)));
}

static long _SYS_chdir(long n, long params[6])
{
    const char* path = (const char*)params[0];

    if (path && !myst_is_bad_addr_read(path, 1))
        _strace(n, "path=\"%s\"", path);
    else
        _strace(n, "path=\"%s\"", "<bad_ptr>");

    return (_return(n, myst_syscall_chdir(path)));
}

static long _SYS_fchdir(long n, long params[6])
{
    int fd = (int)params[0];

    _strace(n, "fd=%d", fd);

    return (_return(n, myst_syscall_fchdir(fd)));
}

static long _SYS_rename(long n, long params[6])
{
    const char* oldpath = (const char*)params[0];
    const char* newpath = (const char*)params[1];

    _strace(n, "oldpath=\"%s\" newpath=\"%s\"", oldpath, newpath);

    return (_return(n, myst_syscall_rename(oldpath, newpath)));
}

static long _SYS_mkdir(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];
    myst_process_t* process = myst_process_self();

    _strace(
        n,
        "pathname=\"%s\" mode=0%o umask=0%o",
        pathname,
        mode,
        process->umask);

    /* Apply umask */
    /* ATTN: Implementaiton need to be updated if directory ACL is
     * supported */
    mode = mode & (~(process->umask));

    return (_return(n, myst_syscall_mkdir(pathname, mode)));
}

static long _SYS_rmdir(long n, long params[6])
{
    const char* pathname = (const char*)params[0];

    _strace(n, "pathname=\"%s\"", pathname);

    return (_return(n, myst_syscall_rmdir(pathname)));
}

static long _SYS_creat(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];
    myst_process_t* process = myst_process_self();

    _strace(
        n,
        "pathname=\"%s\" mode=0%o umask=0%o",
        pathname,
        mode,
        process->umask);

    /* Apply umask */
    /* ATTN: Implementaiton need to be updated if directory ACL is
     * supported */
    mode = mode & (~(process->umask));

    return (_return(n, myst_syscall_creat(pathname, mode)));
}

static long _SYS_link(long n, long params[6])
{
    const char* oldpath = (const char*)params[0];
    const char* newpath = (const char*)params[1];

    _strace(n, "oldpath=\"%s\" newpath=\"%s\"", oldpath, newpath);

    return (_return(n, myst_syscall_link(oldpath, newpath)));
}

static long _SYS_unlink(long n, long params[6])
{
    const char* pathname = (const char*)params[0];

    _strace(n, "pathname=\"%s\"", pathname);

    return (_return(n, myst_syscall_unlink(pathname)));
}

static long _SYS_symlink(long n, long params[6])
{
    const char* target = (const char*)params[0];
    const char* linkpath = (const char*)params[1];

    _strace(n, "target=\"%s\" linkpath=\"%s\"", target, linkpath);

    return (_return(n, myst_syscall_symlink(target, linkpath)));
}

static long _SYS_readlink(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    char* buf = (char*)params[1];
    size_t bufsiz = (size_t)params[2];

    _strace(n, "pathname=\"%s\" buf=%p bufsiz=%zu", pathname, buf, bufsiz);

    return (_return(n, myst_syscall_readlink(pathname, buf, bufsiz)));
}

static long _SYS_chmod(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];

    _strace(n, "pathname=\"%s\" mode=%o", pathname, mode);

    return (_return(n, myst_syscall_chmod(pathname, mode)));
}

static long _SYS_fchmod(long n, long params[6])
{
    int fd = (int)params[0];
    mode_t mode = (mode_t)params[1];

    _strace(n, "fd=%d mode=%o", fd, mode);

    return (_return(n, myst_syscall_fchmod(fd, mode)));
}

static long _SYS_chown(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    uid_t owner = (uid_t)params[1];
    gid_t group = (gid_t)params[2];

    _strace(n, "pathname=%s owner=%u group=%u", pathname, owner, group);

    return (_return(n, myst_syscall_chown(pathname, owner, group)));
}

static long _SYS_fchown(long n, long params[6])
{
    int fd = (int)params[0];
    uid_t owner = (uid_t)params[1];
    gid_t group = (gid_t)params[2];

    _strace(n, "fd=%d owner=%u group=%u", fd, owner, group);

    return (_return(n, myst_syscall_fchown(fd, owner, group)));
}

static long _SYS_fchownat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    uid_t owner = (uid_t)params[2];
    gid_t group = (gid_t)params[3];
    int flags = (int)params[4];

    _strace(
        n,
        "dirfd=%d pathname=%s owner=%u group=%u flags=%d",
        dirfd,
        pathname,
        owner,
        group,
        flags);

    return (_return(
        n, myst_syscall_fchownat(dirfd, pathname, owner, group, flags)));
}

static long _SYS_lchown(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    uid_t owner = (uid_t)params[1];
    gid_t group = (gid_t)params[2];

    if (pathname && !myst_is_bad_addr_read(pathname, 1))
        _strace(n, "pathname=%s owner=%u group=%u", pathname, owner, group);
    else
        _strace(n, "pathname=%s owner=%u group=%u", "<bad_ptr>", owner, group);

    return _return(n, myst_syscall_lchown(pathname, owner, group));
}

static long _SYS_umask(long n, long params[6])
{
    mode_t mask = (mode_t)params[0];

    _strace(n, "mask=%o", mask);

    return (_return(n, myst_syscall_umask(mask)));
}

static long _SYS_gettimeofday(long n, long params[6])
{
    struct timeval* tv = (struct timeval*)params[0];
    struct timezone* tz = (void*)params[1];

    _strace(n, "tv=%p tz=%p", tv, tz);

    long ret = myst_syscall_gettimeofday(tv, tz);
    return (_return(n, ret));
}

static long _SYS_getrusage(long n, long params[6])
{
    int who = (int)params[0];
    struct rusage* usage = (struct rusage*)params[1];
    long ret;

    _strace(n, "who=%d usage=%p", who, usage);

    if (!usage || myst_is_bad_addr_write(usage, sizeof(*usage)))
        ret = -EFAULT;
    else if (
        who != RUSAGE_THREAD && who != RUSAGE_CHILDREN && who != RUSAGE_SELF)
        ret = -EINVAL;
    else
    {
        ret = myst_syscall_getrusage(who, usage);
    }

    return (_return(n, ret));
}

static long _SYS_sysinfo(long n, long params[6])
{
    struct sysinfo* info = (struct sysinfo*)params[0];
    _strace(n, "info=%p", info);
    long ret = myst_syscall_sysinfo(info);
    return (_return(n, ret));
}

static long _SYS_times(long n, long params[6], myst_process_t* process)
{
    struct tms* tm = (struct tms*)params[0];
    _strace(n, "tm=%p", tm);

    struct tms process_tm;
    myst_times_process_times(process, &process_tm);

    long ret = process_tm.tms_stime + process_tm.tms_utime;

    if (tm != NULL)
    {
        if (!myst_is_bad_addr_write(tm, sizeof(struct tms)))
            *tm = process_tm;
        else
            ret = -EFAULT;
    }

    return (_return(n, ret));
}

static long _SYS_syslog(long n, long params[6])
{
    (void)params;

    /* Ignore syslog for now */
    return (_return(n, 0));
}

static long _SYS_setpgid(long n, long params[6], myst_thread_t* thread)
{
    pid_t pid = (pid_t)params[0];
    pid_t pgid = (pid_t)params[1];
    _strace(n, "pid=%u pgid=%u", pid, pgid);
    return (_return(n, myst_syscall_setpgid(pid, pgid, thread)));
}

static long _SYS_getpgid(long n, long params[6], myst_thread_t* thread)
{
    pid_t pid = (pid_t)params[0];
    _strace(n, "pid=%u", pid);
    return (_return(n, myst_syscall_getpgid(pid, thread)));
}

static long _SYS_getpgrp(
    long n,
    long params[6],
    myst_process_t* process,
    myst_thread_t* thread)
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_syscall_getpgid(process->pid, thread)));
}

static long _SYS_getppid(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_getppid()));
}

static long _SYS_getsid(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_getsid()));
}

static long _SYS_setsid(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_syscall_setsid()));
}

static long _SYS_getgroups(long n, long params[6])
{
    size_t size = (size_t)params[0];
    gid_t* list = (gid_t*)params[1];
    /* return the extra groups on the thread */
    _strace(n, NULL);
    return (_return(n, myst_syscall_getgroups(size, list)));
}

static long _SYS_setgroups(long n, long params[6])
{
    int size = (int)params[0];
    const gid_t* list = (const gid_t*)params[1];

    /* return the extra groups on the thread */
    _strace(n, NULL);
    return (_return(n, myst_syscall_setgroups(size, list)));
}

static long _SYS_getuid(long n, long params[6])
{
    (void)params;

    /* return the real uid of the thread */
    _strace(n, NULL);
    return (_return(n, myst_syscall_getuid()));
}

static long _SYS_setuid(long n, long params[6])
{
    /* Set euid and fsuid to arg1, and if euid is already set to root
     * also set uid and savuid of the thread */
    uid_t uid = (uid_t)params[0];
    _strace(n, "uid=%u", uid);

    return (_return(n, myst_syscall_setuid(uid)));
}

static long _SYS_getgid(long n, long params[6])
{
    (void)params;

    /* return the gid of the thread */
    _strace(n, NULL);
    return (_return(n, myst_syscall_getgid()));
}

static long _SYS_setgid(long n, long params[6])
{
    /* set the effective gid (euid) of the thread, unless egid is root
     * in which case set all gids */
    gid_t gid = (gid_t)params[0];
    _strace(n, "gid=%u", gid);
    return (_return(n, myst_syscall_setgid(gid)));
}

static long _SYS_geteuid(long n, long params[6])
{
    (void)params;

    /* return threads effective uid (euid) */
    _strace(n, NULL);
    return (_return(n, myst_syscall_geteuid()));
}

static long _SYS_getegid(long n, long params[6])
{
    (void)params;

    /* return threads effective gid (egid) */
    _strace(n, NULL);
    return (_return(n, myst_syscall_getegid()));
}

static long _SYS_setreuid(long n, long params[6])
{
    /* set the real and effective uid of the thread */
    uid_t ruid = (uid_t)params[0];
    uid_t euid = (uid_t)params[1];
    _strace(n, "Changing IDs to ruid=%u, euid=%u", ruid, euid);
    return (_return(n, myst_syscall_setreuid(ruid, euid)));
}

static long _SYS_setregid(long n, long params[6])
{
    /* set the real and effective uid of the thread */
    gid_t rgid = (gid_t)params[0];
    gid_t egid = (gid_t)params[1];
    _strace(n, "Changing setting to rgid=%u, egid=%u", rgid, egid);
    return (_return(n, myst_syscall_setregid(rgid, egid)));
}

static long _SYS_setresuid(long n, long params[6])
{
    /* set the real and effective uid of the thread */
    uid_t ruid = (uid_t)params[0];
    uid_t euid = (uid_t)params[1];
    uid_t savuid = (uid_t)params[2];
    _strace(
        n,
        "Changing setting to ruid=%u, euid=%u, savuid=%u",
        ruid,
        euid,
        savuid);
    return (_return(n, myst_syscall_setresuid(ruid, euid, savuid)));
}

static long _SYS_getresuid(long n, long params[6])
{
    uid_t* ruid = (uid_t*)params[0];
    uid_t* euid = (uid_t*)params[1];
    uid_t* savuid = (uid_t*)params[2];
    _strace(n, NULL);
    return (_return(n, myst_syscall_getresuid(ruid, euid, savuid)));
}

static long _SYS_setresgid(long n, long params[6])
{
    /* set the real and effective uid of the thread */
    gid_t rgid = (gid_t)params[0];
    gid_t egid = (gid_t)params[1];
    gid_t savgid = (gid_t)params[2];
    _strace(
        n,
        "Changing setting to rgid=%u, egid=%u, savgid=%u",
        rgid,
        egid,
        savgid);
    return (_return(n, myst_syscall_setresgid(rgid, egid, savgid)));
}

static long _SYS_getresgid(long n, long params[6])
{
    gid_t* rgid = (gid_t*)params[0];
    gid_t* egid = (gid_t*)params[1];
    gid_t* savgid = (gid_t*)params[2];
    _strace(n, NULL);
    return (_return(n, myst_syscall_getresgid(rgid, egid, savgid)));
}

static long _SYS_setfsuid(long n, long params[6])
{
    uid_t fsuid = (uid_t)params[0];
    _strace(n, "fsuid=%u", fsuid);
    return (_return(n, myst_syscall_setfsuid(fsuid)));
}

static long _SYS_setfsgid(long n, long params[6])
{
    gid_t fsgid = (gid_t)params[0];
    _strace(n, "fsgid=%u", fsgid);
    return (_return(n, myst_syscall_setfsgid(fsgid)));
}

static long _SYS_rt_sigpending(long n, long params[6])
{
    sigset_t* set = (sigset_t*)params[0];
    unsigned size = (unsigned)params[1];
    _strace(n, "set=%p size=%d", set, size);
    return (_return(n, myst_signal_sigpending(set, size)));
}

static long _SYS_sigaltstack(long n, long params[6])
{
    const stack_t* ss = (stack_t*)params[0];
    stack_t* ss_old = (stack_t*)params[1];
    _strace(n, "altstack=%p altstack_old=%p", ss, ss_old);
    return (_return(n, myst_signal_altstack(ss, ss_old)));
}

static long _SYS_mknod(long n, long params[6])
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];
    dev_t dev = (dev_t)params[2];
    long ret = 0;

    _strace(n, "pathname=%s mode=%d dev=%lu", pathname, mode, dev);

    if (S_ISFIFO(mode))
    {
        /* ATTN: create a pipe here! */
    }
    else
    {
        ret = -ENOTSUP;
    }

    return (_return(n, ret));
}

static long _SYS_statfs(long n, long params[6])
{
    const char* path = (const char*)params[0];
    struct statfs* buf = (struct statfs*)params[1];

    _strace(n, "path=\"%s\" buf=%p", path, buf);

    long ret = myst_syscall_statfs(path, buf);

    return (_return(n, ret));
}

static long _SYS_fstatfs(long n, long params[6])
{
    int fd = (int)params[0];
    struct statfs* buf = (struct statfs*)params[1];

    _strace(n, "fd=%d buf=%p", fd, buf);

    long ret = myst_syscall_fstatfs(fd, buf);

    return (_return(n, ret));
}

static long _SYS_sched_setparam(long n, long params[6])
{
    (void)params;

    /* ATTN: support setting thread priorities. */
    return (_return(n, 0));
}

static long _SYS_sched_getparam(long n, long params[6])
{
    pid_t pid = (pid_t)params[0];
    struct sched_param* param = (struct sched_param*)params[1];

    _strace(n, "pid=%d param=%p", pid, param);

    return (_return(n, myst_syscall_sched_getparam(pid, param)));
}

static long _SYS_sched_setscheduler(long n, long params[6])
{
    (void)params;

    // ATTN: support different schedules, FIFO, RR, BATCH, etc.
    // The more control we have on threads inside the kernel, the more
    // schedulers we could support.
    return (_return(n, 0));
}

static long _SYS_sched_getscheduler(long n, long params[6])
{
    (void)params;

    /* ATTN: return the scheduler installed from sched_setscheduler. */
    return (_return(n, SCHED_OTHER));
}

static long _SYS_sched_get_priority_max(long n, long params[6])
{
    (void)params;

    /* ATTN: support thread priorities */
    return (_return(n, 0));
}

static long _SYS_sched_get_priority_min(long n, long params[6])
{
    (void)params;

    /* ATTN: support thread priorities */
    return (_return(n, 0));
}

static long _SYS_mlock(long n, long params[6])
{
    const void* addr = (const void*)params[0];
    size_t len = (size_t)params[1];
    long ret = 0;

    _strace(n, "addr=%p len=%zu", addr, len);

    if (!addr)
        ret = -EINVAL;

    // ATTN: forward the request to target.
    // Some targets, such as sgx, probably just ignore it.

    return (_return(n, ret));
}

static long _SYS_prctl(long n, long params[6])
{
    int option = (int)params[0];
    long ret = 0;

    _strace(n, "option=%d", option);

    if (option == PR_GET_NAME)
    {
        char* arg2 = (char*)params[1];
        if (!arg2)
            return (_return(n, -EINVAL));

        // ATTN: Linux requires a 16-byte buffer:
        const size_t n = 16;
        myst_strlcpy(arg2, myst_get_thread_name(myst_thread_self()), n);
    }
    else if (option == PR_SET_NAME)
    {
        char* arg2 = (char*)params[1];
        if (!arg2)
            return (_return(n, -EINVAL));

        ret = myst_set_thread_name(myst_thread_self(), arg2);
    }
    else
    {
        ret = -EINVAL;
    }

    return (_return(n, ret));
}

static long _SYS_sync(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_syscall_sync()));
}

static long _SYS_mount(long n, long params[6])
{
    const char* source = (const char*)params[0];
    const char* target = (const char*)params[1];
    const char* filesystemtype = (const char*)params[2];
    unsigned long mountflags = (unsigned long)params[3];
    void* data = (void*)params[4];
    long ret;

    _strace(
        n,
        "source=%s target=%s filesystemtype=%s mountflags=%lu data=%p",
        source,
        target,
        filesystemtype,
        mountflags,
        data);

    ret = myst_syscall_mount(
        source, target, filesystemtype, mountflags, data, false);

    return (_return(n, ret));
}

static long _SYS_umount2(long n, long params[6])
{
    const char* target = (const char*)params[0];
    int flags = (int)params[1];
    long ret;

    _strace(n, "target=%p flags=%d", target, flags);

    ret = myst_syscall_umount2(target, flags);

    return (_return(n, ret));
}

static long _SYS_sethostname(long n, long params[6])
{
    const char* name = (const char*)params[0];
    size_t len = (size_t)params[1];

    _strace(n, "name=\"%s\" len=%zu", name, len);

    return (_return(n, myst_syscall_sethostname(name, len)));
}

static long _SYS_gettid(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, myst_gettid()));
}

static long _SYS_fsetxattr(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);
    return (_return(n, -ENOSYS));
}

static long _SYS_tkill(long n, long params[6], myst_process_t* process)
{
    int tid = (int)params[0];
    int sig = (int)params[1];

    _strace(n, "tid=%d sig=%d(%s)", tid, sig, myst_signum_to_string(sig));

    int tgid = process->pid;

    long ret = myst_syscall_tgkill(tgid, tid, sig);
    return (_return(n, ret));
}

static long _SYS_time(long n, long params[6])
{
    time_t* tloc = (time_t*)params[0];

    _strace(n, "tloc=%p", tloc);
    long ret = myst_syscall_time(tloc);
    return (_return(n, ret));
}

static long _SYS_futex(long n, long params[6])
{
    int* uaddr = (int*)params[0];
    int futex_op = (int)params[1];
    int val = (int)params[2];
    long arg = (long)params[3];
    int* uaddr2 = (int*)params[4];
    int val3 = (int)params[5];
    int futex_op2 = futex_op & ~FUTEX_PRIVATE;

    if (futex_op2 == FUTEX_WAIT || futex_op2 == FUTEX_WAIT_BITSET)
    {
        const struct timespec* timeout = (const struct timespec*)params[3];
        struct timespec_buf buf;

        _strace(
            n,
            "uaddr=0x%lx(%d) futex_op=%u(%s) val=%d, "
            "timeout=%s uaddr2=0x%lx val3=%d",
            (long)uaddr,
            (uaddr ? *uaddr : -1),
            futex_op,
            _futex_op_str(futex_op),
            val,
            _format_timespec(&buf, timeout),
            (long)uaddr2,
            val3);
    }
    else
    {
        _strace(
            n,
            "uaddr=0x%lx(%d) futex_op=%u(%s) val=%d arg=%li "
            "uaddr2=0x%lx val3=%d",
            (long)uaddr,
            (uaddr ? *uaddr : -1),
            futex_op,
            _futex_op_str(futex_op),
            val,
            arg,
            (long)uaddr2,
            val3);
    }

    return (_return(
        n, myst_syscall_futex(uaddr, futex_op, val, arg, uaddr2, val3)));
}

static long _SYS_sched_setaffinity(long n, long params[6])
{
    pid_t pid = (pid_t)params[0];
    size_t cpusetsize = (pid_t)params[1];
    const cpu_set_t* mask = (const cpu_set_t*)params[2];
    long ret;

    _strace(n, "pid=%d cpusetsize=%zu mask=%p", pid, cpusetsize, mask);

    ret = myst_syscall_sched_setaffinity(pid, cpusetsize, mask);
    return (_return(n, ret));
}

static long _SYS_sched_getaffinity(long n, long params[6])
{
    pid_t pid = (pid_t)params[0];
    size_t cpusetsize = (pid_t)params[1];
    cpu_set_t* mask = (cpu_set_t*)params[2];
    long ret;

    _strace(n, "pid=%d cpusetsize=%zu mask=%p", pid, cpusetsize, mask);

    /* returns the number of bytes in the kernel affinity mask */
    ret = myst_syscall_sched_getaffinity(pid, cpusetsize, mask);

    return (_return(n, ret));
}

static long _SYS_set_thread_area(
    long n,
    long params[6],
    myst_td_t** crt_td_out,
    const myst_td_t* target_td,
    myst_thread_t* thread,
    bool* set_thread_area_called)
{
    void* tp = (void*)params[0];

    _strace(n, "tp=%p", tp);

    /* ---------- running target thread descriptor ---------- */

#ifdef DISABLE_MULTIPLE_SET_THREAD_AREA_SYSCALLS
    if (_set_thread_area_called)
        myst_panic("SYS_set_thread_area called twice");
#endif

    /* get the C-runtime thread descriptor */
    (*crt_td_out) = (myst_td_t*)tp;
    assert(myst_valid_td((*crt_td_out)));

    /* set the C-runtime thread descriptor for this thread */
    thread->crt_td = (*crt_td_out);

    /* propagate the canary from the old thread descriptor */
    (*crt_td_out)->canary = target_td->canary;

    *set_thread_area_called = true;

    return (_return(n, 0));
}

static long _SYS_epoll_create(long n, long params[6])
{
    int size = (int)params[0];

    _strace(n, "size=%d", size);

    if (size <= 0)
        return (_return(n, -EINVAL));

    return (_return(n, myst_syscall_epoll_create1(0)));
}

static long _SYS_getdents64(long n, long params[6])
{
    unsigned int fd = (unsigned int)params[0];
    struct dirent* dirp = (struct dirent*)params[1];
    unsigned int count = (unsigned int)params[2];

    _strace(n, "fd=%d dirp=%p count=%u", fd, dirp, count);

    return (_return(n, myst_syscall_getdents64((int)fd, dirp, count)));
}

static long _SYS_set_tid_address(long n, long params[6])
{
    int* tidptr = (int*)params[0];

    /* ATTN: unused */

    _strace(n, "tidptr=%p *tidptr=%d", tidptr, tidptr ? *tidptr : -1);

    return (_return(n, myst_getpid()));
}

static long _SYS_fadvise64(long n, long params[6])
{
    int fd = (int)params[0];
    loff_t offset = (loff_t)params[1];
    loff_t len = (loff_t)params[2];
    int advice = (int)params[3];

    _strace(n, "fd=%d offset=%ld len=%ld advice=%d", fd, offset, len, advice);

    /* ATTN: no-op */
    return (_return(n, 0));
}

static long _SYS_clock_settime(long n, long params[6])
{
    clockid_t clk_id = (clockid_t)params[0];
    struct timespec* tp = (struct timespec*)params[1];
    struct timespec_buf buf;

    _strace(n, "clk_id=%u tp=%s", clk_id, _format_timespec(&buf, tp));

    return (_return(n, myst_syscall_clock_settime(clk_id, tp)));
}

static long _SYS_clock_getres(long n, long params[6])
{
    clockid_t clk_id = (clockid_t)params[0];
    struct timespec* res = (struct timespec*)params[1];

    _strace(n, "clk_id=%u tp=%p", clk_id, res);

    return (_return(n, myst_syscall_clock_getres(clk_id, res)));
}

static long _SYS_epoll_wait(long n, long params[6])
{
    int epfd = (int)params[0];
    struct epoll_event* events = (struct epoll_event*)params[1];
    int maxevents = (int)params[2];
    int timeout = (int)params[3];
    long ret;

    _strace(
        n,
        "edpf=%d events=%p maxevents=%d timeout=%d",
        epfd,
        events,
        maxevents,
        timeout);

    ret = myst_syscall_epoll_wait(epfd, events, maxevents, timeout);
    return (_return(n, ret));
}

static long _SYS_epoll_ctl(long n, long params[6])
{
    int epfd = (int)params[0];
    int op = (int)params[1];
    int fd = (int)params[2];
    struct epoll_event* event = (struct epoll_event*)params[3];
    long ret;

    _strace(n, "edpf=%d op=%d fd=%d event=%p", epfd, op, fd, event);

    ret = myst_syscall_epoll_ctl(epfd, op, fd, event);
    return (_return(n, ret));
}

static long _SYS_tgkill(long n, long params[6])
{
    int tgid = (int)params[0];
    int tid = (int)params[1];
    int sig = (int)params[2];

    _strace(n, "tgid=%d tid=%d sig=%d", tgid, tid, sig);

    long ret = myst_syscall_tgkill(tgid, tid, sig);
    return (_return(n, ret));
}

static long _SYS_mbind(long n, long params[6])
{
    void* addr = (void*)params[0];
    unsigned long len = (unsigned long)params[1];
    int mode = (int)params[2];
    const unsigned long* nodemask = (const unsigned long*)params[3];
    unsigned long maxnode = (unsigned long)params[4];
    unsigned flags = (unsigned)params[5];

    _strace(
        n,
        "addr=%p len=%lu mode=%d nodemask=%p maxnode=%lu flags=%u",
        addr,
        len,
        mode,
        nodemask,
        maxnode,
        flags);

    long ret = myst_syscall_mbind(addr, len, mode, nodemask, maxnode, flags);
    return (_return(n, ret));
}

static long _SYS_waitid(long n, long params[6])
{
    idtype_t idtype = (idtype_t)params[0];
    id_t id = (id_t)params[1];
    siginfo_t* infop = (siginfo_t*)params[2];
    int options = (int)params[3];

    _strace(
        n, "idtype=%i id=%i infop=%p options=%x", idtype, id, infop, options);

    long ret = myst_syscall_waitid(idtype, id, infop, options);
    return (_return(n, ret));
}

static long _SYS_inotify_init(long n, long params[6])
{
    (void)params;

    _strace(n, NULL);

    long ret = myst_syscall_inotify_init1(0);
    return (_return(n, ret));
}

static long _SYS_inotify_add_watch(long n, long params[6])
{
    int fd = (int)params[0];
    const char* pathname = (const char*)params[1];
    uint32_t mask = (uint32_t)params[2];

    _strace(n, "fd=%d pathname=%s mask=%x", fd, pathname, mask);

    long ret = myst_syscall_inotify_add_watch(fd, pathname, mask);
    return (_return(n, ret));
}

static long _SYS_inotify_rm_watch(long n, long params[6])
{
    int fd = (int)params[0];
    int wd = (int)params[1];

    _strace(n, "fd=%d wd=%d", fd, wd);

    long ret = myst_syscall_inotify_rm_watch(fd, wd);
    return (_return(n, ret));
}

static long _SYS_openat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* path = (const char*)params[1];
    int flags = (int)params[2];
    mode_t mode = (mode_t)params[3];
    myst_process_t* process = myst_process_self();
    long ret;

    _strace(
        n,
        "dirfd=%d path=\"%s\" flags=0%o mode=0%o umask=0%o",
        dirfd,
        path,
        flags,
        mode,
        process->umask);

    /* Apply umask */
    /* ATTN: Implementaiton need to be updated if directory ACL is
     * supported */
    mode = mode & (~(process->umask));

    ret = myst_syscall_openat(dirfd, path, flags, mode);

    return (_return(n, ret));
}

static long _SYS_mkdirat(long n, long params[6], myst_process_t* process)
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    mode_t mode = (mode_t)params[2];
    long ret;

    _strace(
        n,
        "dirfd=%d pathname=\"%s\" mode=0%o umask=0%o",
        dirfd,
        pathname,
        mode,
        process->umask);

    /* Apply umask */
    /* ATTN: Implementaiton need to be updated if directory ACL is
     * supported */
    mode = mode & (~(process->umask));

    ret = myst_syscall_mkdirat(dirfd, pathname, mode);

    return (_return(n, ret));
}

static long _SYS_futimesat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    const struct timeval* times = (const struct timeval*)params[2];
    long ret;
    if (_trace_syscall(SYS_futimesat))
    {
        const struct timeval* _times = times;
        if (times && myst_is_bad_addr_read(times, sizeof(struct timeval)))
        {
            _times = NULL;
        }
        _strace(
            n,
            "dirfd=%d pathname=%s times=%p(sec=%ld, usec=%ld)",
            dirfd,
            pathname,
            times,
            _times ? times->tv_sec : 0,
            _times ? times->tv_usec : 0);
    }

    ret = myst_syscall_futimesat(dirfd, pathname, times);
    return (_return(n, ret));
}

static long _SYS_newfstatat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    struct stat* statbuf = (struct stat*)params[2];
    int flags = (int)params[3];
    long ret;

    _strace(
        n,
        "dirfd=%d pathname=%s statbuf=%p flags=%d",
        dirfd,
        pathname,
        statbuf,
        flags);

    ret = myst_syscall_fstatat(dirfd, pathname, statbuf, flags);
    return (_return(n, ret));
}

static long _SYS_unlinkat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    int flags = (int)params[2];

    _strace(n, "dirfd=%d pathname=%s flags=%d", dirfd, pathname, flags);

    return (_return(n, myst_syscall_unlinkat(dirfd, pathname, flags)));
}

static long _SYS_renameat(long n, long params[6])
{
    int olddirfd = (int)params[0];
    const char* oldpath = (const char*)params[1];
    int newdirfd = (int)params[2];
    const char* newpath = (const char*)params[3];

    _strace(
        n,
        "olddirfd=%d oldpath=\"%s\" newdirfd=%d newpath=\"%s\"",
        olddirfd,
        oldpath,
        newdirfd,
        newpath);

    return (_return(
        n, myst_syscall_renameat(olddirfd, oldpath, newdirfd, newpath)));
}

static long _SYS_linkat(long n, long params[6])
{
    int olddirfd = (int)params[0];
    const char* oldpath = (const char*)params[1];
    int newdirfd = (int)params[2];
    const char* newpath = (const char*)params[3];
    int flags = (int)params[4];

    _strace(
        n,
        "olddirfd=%d oldpath=%s newdirfd=%d newpath=%s flags=%d",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags);

    return (_return(
        n, myst_syscall_linkat(olddirfd, oldpath, newdirfd, newpath, flags)));
}

static long _SYS_symlinkat(long n, long params[6])
{
    const char* target = (const char*)params[0];
    int newdirfd = (int)params[1];
    const char* linkpath = (const char*)params[2];

    _strace(n, "target=%s newdirfd=%d linkpath=%s", target, newdirfd, linkpath);

    return (_return(n, myst_syscall_symlinkat(target, newdirfd, linkpath)));
}

static long _SYS_readlinkat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    char* buf = (char*)params[2];
    size_t bufsiz = (size_t)params[3];

    _strace(
        n,
        "dirfd=%d pathname=%s buf=%p bufsize=%ld",
        dirfd,
        pathname,
        buf,
        bufsiz);

    return (_return(n, myst_syscall_readlinkat(dirfd, pathname, buf, bufsiz)));
}

static long _SYS_fchmodat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    mode_t mode = (mode_t)params[2];
    int flags = (int)params[3];
    long ret;

    _strace(
        n,
        "dirfd=%d pathname=\"%s\" mode=0%o flags=0%o",
        dirfd,
        pathname,
        mode,
        flags);

    ret = myst_syscall_fchmodat(dirfd, pathname, mode, flags);

    return (_return(n, ret));
}

static long _SYS_faccessat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    int mode = (int)params[2];
    int flags = (int)params[3];

    _strace(
        n,
        "dirfd=%d pathname=%s mode=%d flags=%d",
        dirfd,
        pathname,
        mode,
        flags);

    return (_return(n, myst_syscall_faccessat(dirfd, pathname, mode, flags)));
}

static long _SYS_ppoll(long n, long params[6], myst_process_t* process)
{
    struct pollfd* fds = (struct pollfd*)params[0];
    nfds_t nfds = (nfds_t)params[1];
    const struct timespec* timeout_ts = (const struct timespec*)params[2];
    const sigset_t* sigmask = (const sigset_t*)params[3];
    long timeout;
    long ret;
    struct timespec_buf buf;
    sigset_t origmask;
    struct rlimit rlimit;

    _strace(
        n,
        "fds=%p nfds=%ld timeout=%s, sigmask=%p",
        fds,
        nfds,
        _format_timespec(&buf, timeout_ts),
        sigmask);

    if ((ret = myst_limit_get_rlimit(process->pid, RLIMIT_NOFILE, &rlimit)) !=
        0)
    {
        /* Shouldnt happen, but still need to fail */
    }
    else if (sigmask && myst_is_bad_addr_read_write(sigmask, sizeof(*sigmask)))
        ret = -EFAULT;
    else if (
        timeout_ts &&
        myst_is_bad_addr_read_write(timeout_ts, sizeof(*timeout_ts)))
        ret = -EFAULT;
    else if (nfds > rlimit.rlim_max)
        ret = -EINVAL;
    else if (
        nfds && fds && myst_is_bad_addr_read_write(fds, sizeof(*fds) * nfds))
        ret = -EFAULT;
    else
    {
        timeout =
            (timeout_ts == NULL)
                ? -1
                : (timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000);
        myst_signal_sigprocmask(SIG_SETMASK, sigmask, &origmask);

        ret = myst_syscall_poll(fds, nfds, timeout, false);

        myst_signal_sigprocmask(SIG_SETMASK, &origmask, NULL);
    }

    return (_return(n, ret));
}

static long _SYS_set_robust_list(long n, long params[6])
{
    struct myst_robust_list_head* head = (void*)params[0];
    size_t len = (size_t)params[1];
    long ret;

    _strace(n, "head=%p len=%zu", head, len);

    ret = myst_syscall_set_robust_list(head, len);
    return (_return(n, ret));
}

static long _SYS_get_robust_list(long n, long params[6])
{
    int pid = (int)params[0];
    struct myst_robust_list_head** head_ptr = (void*)params[1];
    size_t* len_ptr = (size_t*)params[2];
    long ret;

    _strace(n, "pid=%d head=%p len=%p", pid, head_ptr, len_ptr);

    ret = myst_syscall_get_robust_list(pid, head_ptr, len_ptr);
    return (_return(n, ret));
}

static long _SYS_utimensat(long n, long params[6])
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    const struct timespec* times = (const struct timespec*)params[2];
    int flags = (int)params[3];
    long ret;

    _strace(
        n,
        "dirfd=%d pathname=%s times=%p flags=%o",
        dirfd,
        pathname,
        times,
        flags);

    ret = myst_syscall_utimensat(dirfd, pathname, times, flags);
    return (_return(n, ret));
}

static long _SYS_epoll_pwait(long n, long params[6])
{
    int epfd = (int)params[0];
    struct epoll_event* events = (struct epoll_event*)params[1];
    int maxevents = (int)params[2];
    int timeout = (int)params[3];
    const sigset_t* sigmask = (const sigset_t*)params[4];
    long ret;

    _strace(
        n,
        "edpf=%d events=%p maxevents=%d timeout=%d sigmask=%p",
        epfd,
        events,
        maxevents,
        timeout,
        sigmask);

    /* ATTN: ignore sigmask */
    ret = myst_syscall_epoll_wait(epfd, events, maxevents, timeout);
    return (_return(n, ret));
}

static long _SYS_fallocate(long n, long params[6])
{
    int fd = (int)params[0];
    int mode = (int)params[1];
    off_t offset = (off_t)params[2];
    off_t len = (off_t)params[3];

    _strace(n, "fd=%d mode=%d offset=%ld len=%ld", fd, mode, offset, len);

    /* ATTN: treated as advisory only */
    return (_return(n, 0));
}

static long _SYS_accept4(long n, long params[6])
{
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    int flags = (int)params[3];
    long ret;

    if (_trace_syscall(SYS_accept4))
    {
        char addrstr[MAX_IPADDR_LEN];

        _socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN);

        _strace(
            n,
            "sockfd=%d addr=%s addrlen=%p flags=0%o",
            sockfd,
            addrstr,
            addrlen,
            flags);
    }

    ret = myst_syscall_accept4(sockfd, addr, addrlen, flags);
    return (_return(n, ret));
}

static long _SYS_eventfd2(long n, long params[6])
{
    unsigned int initval = (unsigned int)params[0];
    int flags = (int)params[1];

    _strace(n, "initval=%u flags=%d", initval, flags);

    long ret = myst_syscall_eventfd(initval, flags);
    return (_return(n, ret));
}

static long _SYS_epoll_create1(long n, long params[6])
{
    int flags = (int)params[0];

    _strace(n, "flags=%d", flags);
    return (_return(n, myst_syscall_epoll_create1(flags)));
}

static long _SYS_pipe2(long n, long params[6])
{
    int* pipefd = (int*)params[0];
    int flags = (int)params[1];
    long ret;

    _strace(n, "pipefd=%p flags=%0o", pipefd, flags);
    ret = myst_syscall_pipe2(pipefd, flags);

    if (_trace_syscall(SYS_pipe2))
        myst_eprintf("    pipefd[]=[%d:%d]\n", pipefd[0], pipefd[1]);

    return (_return(n, ret));
}

static long _SYS_inotify_init1(long n, long params[6])
{
    int flags = (int)params[0];

    _strace(n, "flags=%x", flags);

    long ret = myst_syscall_inotify_init1(flags);
    return (_return(n, ret));
}

static long _SYS_preadv(long n, long params[6])
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];
    off_t offset = (off_t)params[3];

    _strace(n, "fd=%d iov=%p iovcnt=%d offset=%zu", fd, iov, iovcnt, offset);

    long ret = myst_syscall_preadv2(fd, iov, iovcnt, offset, 0);
    return (_return(n, ret));
}

static long _SYS_pwritev(long n, long params[6])
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];
    off_t offset = (off_t)params[3];

    _strace(n, "fd=%d iov=%p iovcnt=%d offset=%zu", fd, iov, iovcnt, offset);

    long ret = myst_syscall_pwritev2(fd, iov, iovcnt, offset, 0);
    return (_return(n, ret));
}

static long _SYS_recvmmsg(long n, long params[6])
{
    int sockfd = (int)params[0];
    struct mmsghdr* msgvec = (struct mmsghdr*)params[1];
    unsigned int vlen = (unsigned int)params[2];
    int flags = (int)params[3];
    struct timespec* timeout = (struct timespec*)params[4];
    long ret;
    struct timespec_buf buf;

    _strace(
        n,
        "sockfd=%d msgvec=%p vlen=%u flags=%d timeout=%s",
        sockfd,
        msgvec,
        vlen,
        flags,
        _format_timespec(&buf, timeout));

    ret = myst_syscall_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    return (_return(n, ret));
}

static long _SYS_prlimit64(long n, long params[6])
{
    int pid = (int)params[0];
    int resource = (int)params[1];
    struct rlimit* new_rlim = (struct rlimit*)params[2];
    struct rlimit* old_rlim = (struct rlimit*)params[3];

    _strace(
        n,
        "pid=%d, resource=%d, new_rlim=%p, old_rlim=%p",
        pid,
        resource,
        new_rlim,
        old_rlim);

    int ret = myst_syscall_prlimit64(pid, resource, new_rlim, old_rlim);
    return (_return(n, ret));
}

static long _SYS_sendmmsg(long n, long params[6], myst_thread_t* thread)
{
    int sockfd = (int)params[0];
    struct mmsghdr* msgvec = (struct mmsghdr*)params[1];
    unsigned int vlen = (unsigned int)params[2];
    int flags = (int)params[3];
    long ret;

    _strace(
        n, "sockfd=%d msgvec=%p vlen=%u flags=%d", sockfd, msgvec, vlen, flags);

    /* Note: We send in MSG_NOSIGNAL so it does not generate a SIGPIPE
     * in the host. We get an EPIPE error back if the socket got closed,
     * and then we will generate the signal ourselves if needed. */
    ret = myst_syscall_sendmmsg(sockfd, msgvec, vlen, flags | MSG_NOSIGNAL);
    if (ret == -EPIPE && !(flags & MSG_NOSIGNAL))
    {
        myst_signal_deliver(thread, SIGPIPE, NULL);
    }
    return (_return(n, ret));
}

static long _SYS_getcpu(long n, long params[6])
{
    unsigned* cpu = (unsigned*)params[0];
    unsigned* node = (unsigned*)params[1];
    struct getcpu_cache* tcache = (struct getcpu_cache*)params[2];
    long ret;

    _strace(n, "cpu=%p node=%p, tcache=%p", cpu, node, tcache);

    /* unused since Linux 2.6.24 */
    (void)tcache;

    ret = myst_syscall_getcpu(cpu, node);
    return (_return(n, ret));
}

static long _SYS_getrandom(long n, long params[6])
{
    void* buf = (void*)params[0];
    size_t buflen = (size_t)params[1];
    unsigned int flags = (unsigned int)params[2];

    _strace(n, "buf=%p buflen=%zu flags=%d", buf, buflen, flags);

    return (_return(n, myst_syscall_getrandom(buf, buflen, flags)));
}

static long _SYS_execveat(
    long n,
    long params[6],
    myst_thread_t* thread,
    syscall_args_t* args)
{
    int dirfd = (int)params[0];
    const char* filename = (const char*)params[1];
    char** argv = (char**)params[2];
    char** envp = (char**)params[3];
    int flags = (int)params[4];

    _strace(
        n,
        "dirfd=%d filename=%s argv=%p envp=%p flags=%d",
        dirfd,
        filename,
        argv,
        envp,
        flags);

    long ret =
        myst_syscall_execveat(dirfd, filename, argv, envp, flags, thread, args);

    return (_return(n, ret));
}

static long _SYS_membarrier(long n, long params[6])
{
    int cmd = (int)params[0];
    int flags = (int)params[1];

    _strace(n, "cmd=%d flags=%d", cmd, flags);
    /* membarrier syscall relies on inter-processor-interrupt and the
     * untrusted privileged SW layer such as the hypervisor or bare
     * metal OS to sychronize code execution across CPU cores. Not
     * supported.
     */
    return (_return(n, -ENOSYS));
}

static long _SYS_copy_file_range(long n, long params[6])
{
    int fd_in = (int)params[0];
    off64_t* off_in = (off64_t*)params[1];
    int fd_out = (int)params[2];
    off64_t* off_out = (off64_t*)params[3];
    size_t len = (size_t)params[4];
    unsigned int flags = (unsigned int)params[5];

    _strace(
        n,
        "fd_in=%d off_in=%ln fd_out=%d off_out=%ln len=%lo flags=%d",
        fd_in,
        off_in,
        fd_out,
        off_out,
        len,
        flags);

    return (_return(
        n,
        myst_syscall_copy_file_range(
            fd_in, off_in, fd_out, off_out, len, flags)));
}

static long _SYS_preadv2(long n, long params[6])
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];
    off_t offset = (off_t)params[3];
    int flags = (int)params[4];

    _strace(n, "fd=%d iov=%p iovcnt=%d offset=%zu", fd, iov, iovcnt, offset);

    long ret = myst_syscall_preadv2(fd, iov, iovcnt, offset, flags);
    return (_return(n, ret));
}

static long _SYS_pwritev2(long n, long params[6])
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];
    off_t offset = (off_t)params[3];
    int flags = (int)params[4];

    _strace(n, "fd=%d iov=%p iovcnt=%d offset=%zu", fd, iov, iovcnt, offset);

    long ret = myst_syscall_pwritev2(fd, iov, iovcnt, offset, flags);
    return (_return(n, ret));
}

static long _SYS_bind(long n, long params[6])
{
    int sockfd = (int)params[0];
    const struct sockaddr* addr = (const struct sockaddr*)params[1];
    socklen_t addrlen = (socklen_t)params[2];
    long ret;

    if (_trace_syscall(SYS_bind))
    {
        char addrstr[MAX_IPADDR_LEN];

        _socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN);

        _strace(n, "sockfd=%d addr=%s addrlen=%u", sockfd, addrstr, addrlen);
    }

    ret = myst_syscall_bind(sockfd, addr, addrlen);
    return (_return(n, ret));
}

static long _SYS_connect(long n, long params[6])
{
    /* connect() and bind() have the same parameters */
    int sockfd = (int)params[0];
    const struct sockaddr* addr = (const struct sockaddr*)params[1];
    socklen_t addrlen = (socklen_t)params[2];
    long ret;

    if (_trace_syscall(SYS_connect))
    {
        char addrstr[MAX_IPADDR_LEN];

        if (_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN) == 0)
        {
            _strace(
                n,
                "sockfd=%d addrlen=%u family=%u ip=%s",
                sockfd,
                addrlen,
                addr->sa_family,
                addrstr);
        }
        else
        {
            _strace(
                n,
                "sockfd=%d addrlen=%u family=<bad> ip=%s",
                sockfd,
                addrlen,
                addrstr);
        }
    }

    ret = myst_syscall_connect(sockfd, addr, addrlen);
    return (_return(n, ret));
}

static long _SYS_recvfrom(long n, long params[6])
{
    int sockfd = (int)params[0];
    void* buf = (void*)params[1];
    size_t len = (size_t)params[2];
    int flags = (int)params[3];
    struct sockaddr* src_addr = (struct sockaddr*)params[4];
    socklen_t* addrlen = (socklen_t*)params[5];
    long ret = 0;

    if (_trace_syscall(SYS_recvfrom))
    {
        char addrstr[MAX_IPADDR_LEN];

        _socketaddr_to_str(src_addr, addrstr, MAX_IPADDR_LEN);

        _strace(
            n,
            "sockfd=%d buf=%p len=%zu flags=%d src_addr=%s addrlen=%p",
            sockfd,
            buf,
            len,
            flags,
            addrstr,
            addrlen);
    }

    ret = myst_syscall_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    return (_return(n, ret));
}

static long _SYS_sendto(long n, long params[6], myst_thread_t* thread)
{
    int sockfd = (int)params[0];
    void* buf = (void*)params[1];
    size_t len = (size_t)params[2];
    int flags = (int)params[3];
    struct sockaddr* dest_addr = (struct sockaddr*)params[4];
    socklen_t addrlen = (socklen_t)params[5];
    long ret = 0;

    if (_trace_syscall(SYS_sendto))
    {
        char addrstr[MAX_IPADDR_LEN];

        // Normal validation happens at lower level, but we need to do
        // this here so logging does not break a test
        _socketaddr_to_str(dest_addr, addrstr, MAX_IPADDR_LEN);

        _strace(
            n,
            "sockfd=%d buf=%p len=%zu flags=%d dest_addr=%s addrlen=%u",
            sockfd,
            buf,
            len,
            flags,
            addrstr,
            addrlen);
    }

    /* Note: We send in MSG_NOSIGNAL so it does not generate a SIGPIPE
     * in the host. We get an EPIPE error back if the socket got closed,
     * and then we will generate the signal ourselves if needed. */
    ret = myst_syscall_sendto(
        sockfd, buf, len, flags | MSG_NOSIGNAL, dest_addr, addrlen);
    if (ret == -EPIPE && !(flags & MSG_NOSIGNAL))
    {
        myst_signal_deliver(thread, SIGPIPE, NULL);
    }

    return (_return(n, ret));
}

static long _SYS_socket(long n, long params[6])
{
    int domain = (int)params[0];
    int type = (int)params[1];
    int protocol = (int)params[2];
    long ret;

    if (_trace_syscall(n))
    {
        char buf[64];

        _strace(
            n,
            "domain=%d(%s) type=%o(%s) protocol=%d",
            domain,
            myst_socket_domain_str(domain),
            type,
            myst_format_socket_type(buf, sizeof(buf), type),
            protocol);
    }

    ret = myst_syscall_socket(domain, type, protocol);
    return (_return(n, ret));
}

static long _SYS_accept(long n, long params[6])
{
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    long ret;

    if (_trace_syscall(SYS_accept))
    {
        char addrstr[MAX_IPADDR_LEN];

        _socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN);

        _strace(n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);
    }

    ret = myst_syscall_accept4(sockfd, addr, addrlen, 0);
    return (_return(n, ret));
}

static long _SYS_sendmsg(long n, long params[6], myst_thread_t* thread)
{
    int sockfd = (int)params[0];
    const struct msghdr* msg = (const struct msghdr*)params[1];
    int flags = (int)params[2];
    long ret;

    if (msg && myst_is_addr_within_kernel(msg))
        if (msg->msg_iov && myst_is_addr_within_kernel(msg->msg_iov))
            _strace(
                n,
                "sockfd=%d msg=%p flags=%d(0x%x) (msg_iov=%p "
                "msg_iovlen=%d total-iov-length=%zd)",
                sockfd,
                msg,
                flags,
                flags,
                msg->msg_iov,
                msg->msg_iovlen,
                myst_iov_len(msg->msg_iov, msg->msg_iovlen));
        else
            _strace(
                n,
                "sockfd=%d msg=%p flags=%d(0x%x) (msg_iov=%p "
                "iov-lengh=%d)",
                sockfd,
                msg,
                flags,
                flags,
                msg->msg_iov,
                msg->msg_iovlen);
    else
        _strace(n, "sockfd=%d msg=%p flags=%d(%x)", sockfd, msg, flags, flags);

    ret = myst_syscall_sendmsg(sockfd, msg, flags | MSG_NOSIGNAL);
    if (ret == -EPIPE && !(flags & MSG_NOSIGNAL))
    {
        myst_signal_deliver(thread, SIGPIPE, NULL);
    }
    return (_return(n, ret));
}

static long _SYS_recvmsg(long n, long params[6])
{
    int sockfd = (int)params[0];
    struct msghdr* msg = (struct msghdr*)params[1];
    int flags = (int)params[2];
    long ret;

    _strace(n, "sockfd=%d msg=%p flags=%d", sockfd, msg, flags);

    ret = myst_syscall_recvmsg(sockfd, msg, flags);
    return (_return(n, ret));
}

static long _SYS_shutdown(long n, long params[6])
{
    int sockfd = (int)params[0];
    int how = (int)params[1];
    long ret;

    _strace(n, "sockfd=%d how=%d", sockfd, how);

    if (__myst_kernel_args.perf)
        myst_print_syscall_times("SYS_shutdown", 10);

    ret = myst_syscall_shutdown(sockfd, how);
    return (_return(n, ret));
}

static long _SYS_listen(long n, long params[6])
{
    int sockfd = (int)params[0];
    int backlog = (int)params[1];
    long ret;

    _strace(n, "sockfd=%d backlog=%d", sockfd, backlog);

    if (__myst_kernel_args.perf)
        myst_print_syscall_times("SYS_listen", 10);

    ret = myst_syscall_listen(sockfd, backlog);
    return (_return(n, ret));
}

static long _SYS_getsockname(long n, long params[6])
{
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    long ret;

    if (_trace_syscall(SYS_getsockname))
    {
        char addrstr[MAX_IPADDR_LEN];

        _socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN);

        _strace(n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);
    }

    ret = myst_syscall_getsockname(sockfd, addr, addrlen);
    return (_return(n, ret));
}

static long _SYS_getpeername(long n, long params[6])
{
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    long ret;

    if (_trace_syscall(SYS_getpeername))
    {
        char addrstr[MAX_IPADDR_LEN];

        _socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN);

        _strace(n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);
    }

    ret = myst_syscall_getpeername(sockfd, addr, addrlen);
    return (_return(n, ret));
}

static long _SYS_socketpair(long n, long params[6])
{
    int domain = (int)params[0];
    int type = (int)params[1];
    int protocol = (int)params[2];
    int* sv = (int*)params[3];
    long ret;

    if (_trace_syscall(n))
    {
        char buf[64];

        _strace(
            n,
            "domain=%d(%s) type=%d(%s) protocol=%d sv=%p",
            domain,
            myst_socket_domain_str(domain),
            type,
            myst_format_socket_type(buf, sizeof(buf), type),
            protocol,
            sv);
    }

    ret = myst_syscall_socketpair(domain, type, protocol, sv);
    return (_return(n, ret));
}

static long _SYS_setsockopt(long n, long params[6])
{
    int sockfd = (int)params[0];
    int level = (int)params[1];
    int optname = (int)params[2];
    const void* optval = (const void*)params[3];
    socklen_t optlen = (socklen_t)params[4];
    long ret;

    _strace(
        n,
        "sockfd=%d level=%d optname=%d optval=%p optlen=%u",
        sockfd,
        level,
        optname,
        optval,
        optlen);

    ret = myst_syscall_setsockopt(sockfd, level, optname, optval, optlen);
    return (_return(n, ret));
}

static long _SYS_getsockopt(long n, long params[6])
{
    int sockfd = (int)params[0];
    int level = (int)params[1];
    int optname = (int)params[2];
    void* optval = (void*)params[3];
    socklen_t* optlen = (socklen_t*)params[4];
    long ret;

    _strace(
        n,
        "sockfd=%d level=%d optname=%d optval=%p optlen=%p",
        sockfd,
        level,
        optname,
        optval,
        optlen);

    ret = myst_syscall_getsockopt(sockfd, level, optname, optval, optlen);
    return (_return(n, ret));
}

static long _SYS_sendfile(long n, long params[6])
{
    int out_fd = (int)params[0];
    int in_fd = (int)params[1];
    off_t* offset = (off_t*)params[2];
    size_t count = (size_t)params[3];
    off_t off = offset ? *offset : 0;

    _strace(
        n,
        "out_fd=%d in_fd=%d offset=%p *offset=%ld count=%zu",
        out_fd,
        in_fd,
        offset,
        off,
        count);

    long ret = myst_syscall_sendfile(out_fd, in_fd, offset, count);
    return (_return(n, ret));
}

#define BREAK(RET)           \
    do                       \
    {                        \
        syscall_ret = (RET); \
        goto done;           \
    } while (0)

static long _syscall(void* args_)
{
    syscall_args_t* args = (syscall_args_t*)args_;
    long n = args->n;
    long* params = args->params;
    long syscall_ret = 0;
    static bool _set_thread_area_called;
    myst_td_t* target_td = NULL;
    myst_td_t* crt_td = NULL;
    myst_thread_t* thread = NULL;
    myst_process_t* process = NULL;

    myst_times_enter_kernel(n);

    /* resolve the target-thread-descriptor and the crt-thread-descriptor */
    if (_set_thread_area_called)
    {
        /* ---------- running C-runtime thread descriptor ---------- */

        /* get crt_td */
        crt_td = myst_get_fsbase();
        myst_assume(myst_valid_td(crt_td));

        /* get thread */
        myst_assume(myst_tcall_get_tsd((uint64_t*)&thread) == 0);
        myst_assume(myst_valid_thread(thread));

        /* get target_td */
        target_td = thread->target_td;
        myst_assume(myst_valid_td(target_td));

        /* the syscall on the target thread descriptor */
        myst_set_fsbase(target_td);
    }
    else
    {
        /* ---------- running target thread descriptor ---------- */

        /* get target_td */
        target_td = myst_get_fsbase();
        myst_assume(myst_valid_td(target_td));

        /* get thread */
        myst_assume(myst_tcall_get_tsd((uint64_t*)&thread) == 0);
        myst_assume(myst_valid_thread(thread));

        /* crt_td is null */
    }

    process = thread->process;

    /* update the user_rsp in the thread structure */
    thread->user_rsp = args->user_rsp;

    // Process signals pending for this thread, if there is any.
    myst_signal_process(thread);

    /* ---------- running target thread descriptor ---------- */

    myst_assume(target_td != NULL);
    myst_assume(thread != NULL);

    switch (n)
    {
        case SYS_myst_trace:
        {
            BREAK(_SYS_myst_trace(n, params));
        }
        case SYS_myst_trace_ptr:
        {
            BREAK(_SYS_myst_trace_ptr(n, params));
        }
        case SYS_myst_dump_stack:
        {
            BREAK(_SYS_myst_dump_stack(n, params));
        }
        case SYS_myst_dump_ehdr:
        {
            BREAK(_SYS_myst_dump_ehdr(n, params));
        }
        case SYS_myst_dump_argv:
        {
            BREAK(_SYS_myst_dump_argv(n, params));
        }
        case SYS_myst_add_symbol_file:
        {
            BREAK(_SYS_myst_add_symbol_file(n, params));
        }
        case SYS_myst_load_symbols:
        {
            BREAK(_SYS_myst_load_symbols(n, params));
        }
        case SYS_myst_unload_symbols:
        {
            BREAK(_SYS_myst_unload_symbols(n, params));
        }
        case SYS_myst_gen_creds:
        {
            BREAK(_SYS_myst_gen_creds(n, params));
        }
        case SYS_myst_free_creds:
        {
            BREAK(_SYS_myst_free_creds(n, params));
        }
        case SYS_myst_gen_creds_ex:
        {
            BREAK(_SYS_myst_gen_creds_ex(n, params));
        }
        case SYS_myst_verify_cert:
        {
            BREAK(_SYS_myst_verify_cert(n, params));
        }
        case SYS_myst_max_threads:
        {
            BREAK(_SYS_myst_max_threads(n, params));
        }
        case SYS_myst_poll_wake:
        {
            BREAK(_SYS_myst_poll_wake(n, params));
        }
#ifdef MYST_ENABLE_GCOV
        case SYS_myst_gcov:
        {
            BREAK(_SYS_myst_gcov(n, params));
        }
#endif
        case SYS_myst_unmap_on_exit:
        {
            BREAK(_SYS_myst_unmap_on_exit(n, params, thread));
        }
        case SYS_myst_get_exec_stack_option:
        {
            BREAK(_SYS_myst_get_exec_stack_option(n, params));
        }
        case SYS_myst_get_process_thread_stack:
        {
            BREAK(_SYS_myst_get_process_thread_stack(n, params));
        }
        case SYS_read:
        {
            BREAK(_SYS_read(n, params));
        }
        case SYS_write:
        {
            BREAK(_SYS_write(n, params));
        }
        case SYS_pread64:
        {
            BREAK(_SYS_pread64(n, params));
        }
        case SYS_pwrite64:
        {
            BREAK(_SYS_pwrite64(n, params));
        }
        case SYS_open:
        {
            BREAK(_SYS_open(n, params));
        }
        case SYS_close:
        {
            BREAK(_SYS_close(n, params));
        }
        case SYS_stat:
        {
            BREAK(_SYS_stat(n, params));
        }
        case SYS_fstat:
        {
            BREAK(_SYS_fstat(n, params));
        }
        case SYS_lstat:
        {
            BREAK(_SYS_lstat(n, params));
        }
        case SYS_poll:
        {
            BREAK(_SYS_poll(n, params));
        }
        case SYS_lseek:
        {
            BREAK(_SYS_lseek(n, params));
        }
        case SYS_mmap:
        {
            BREAK(_SYS_mmap(n, params, process));
        }
        case SYS_mprotect:
        {
            BREAK(_SYS_mprotect(n, params));
        }
        case SYS_munmap:
        {
            BREAK(_SYS_munmap(n, params, thread, crt_td));
        }
        case SYS_brk:
        {
            BREAK(_SYS_brk(n, params));
        }
        case SYS_rt_sigaction:
        {
            BREAK(_SYS_rt_sigaction(n, params));
        }
        case SYS_rt_sigprocmask:
        {
            BREAK(_SYS_rt_sigprocmask(n, params));
        }
        case SYS_rt_sigreturn:
            break;
        case SYS_ioctl:
        {
            BREAK(_SYS_ioctl(n, params));
        }
        case SYS_readv:
        {
            BREAK(_SYS_readv(n, params));
        }
        case SYS_writev:
        {
            BREAK(_SYS_writev(n, params));
        }
        case SYS_access:
        {
            BREAK(_SYS_access(n, params));
        }
        case SYS_pipe:
        {
            BREAK(_SYS_pipe(n, params));
        }
        case SYS_select:
        {
            BREAK(_SYS_select(n, params));
        }
        case SYS_sched_yield:
        {
            BREAK(_SYS_sched_yield(n, params));
        }
        case SYS_mremap:
        {
            BREAK(_SYS_mremap(n, params));
        }
        case SYS_msync:
        {
            BREAK(_SYS_msync(n, params));
        }
        case SYS_mincore:
            break;
        case SYS_madvise:
        {
            BREAK(_SYS_madvise(n, params));
        }
        case SYS_shmget:
            break;
        case SYS_shmat:
            break;
        case SYS_shmctl:
            break;
        case SYS_dup:
        {
            BREAK(_SYS_dup(n, params));
        }
        case SYS_dup2:
        {
            BREAK(_SYS_dup2(n, params));
        }
        case SYS_dup3:
        {
            BREAK(_SYS_dup3(n, params));
        }
        case SYS_pause:
        {
            BREAK(_SYS_pause(n, params));
        }
        case SYS_nanosleep:
        {
            BREAK(_SYS_nanosleep(n, params));
        }
        case SYS_myst_run_itimer:
        {
            BREAK(_SYS_myst_run_itimer(n, params, process));
        }
        case SYS_myst_start_shell:
        {
            BREAK(_SYS_myst_start_shell(n, params));
        }
        case SYS_getitimer:
        {
            BREAK(_SYS_getitimer(n, params, process));
        }
        case SYS_alarm:
            break;
        case SYS_setitimer:
        {
            BREAK(_SYS_setitimer(n, params, process));
        }
        case SYS_getpid:
        {
            BREAK(_SYS_getpid(n, params));
        }
        case SYS_clone:
        {
            /* unsupported: using SYS_myst_clone instead */
            break;
        }
        case SYS_myst_clone:
        {
            BREAK(_SYS_myst_clone(n, params));
        }
        case SYS_myst_get_fork_info:
        {
            BREAK(_SYS_myst_get_fork_info(n, params, process));
        }
        case SYS_myst_interrupt_thread:
        {
            BREAK(_SYS_myst_interrupt_thread(n, params));
        }
        case SYS_myst_fork_wait_exec_exit:
        {
            BREAK(_SYS_myst_fork_wait_exec_exit(n, params, thread));
        }
        case SYS_myst_kill_wait_child_forks:
        {
            BREAK(_SYS_myst_kill_wait_child_forks(n, params, process));
        }
        case SYS_myst_pre_launch_hook:
        {
            _strace(n, NULL);

            if (__myst_kernel_args.perf || __myst_kernel_args.trace_times)
                _print_app_load_time();

            BREAK(_return(n, 0));
        }
        case SYS_fork:
            break;
        case SYS_vfork:
            break;
        case SYS_execve:
        {
            BREAK(_SYS_execve(n, params, thread, args));
        }
        case SYS_exit:
        case SYS_exit_group:
        {
            BREAK(_SYS_exit_group(n, params, args, thread, process));
        }
        case SYS_wait4:
        {
            BREAK(_SYS_wait4(n, params));
        }
        case SYS_kill:
        {
            BREAK(_SYS_kill(n, params));
        }
        case SYS_uname:
        {
            BREAK(_SYS_uname(n, params));
        }
        case SYS_semget:
            break;
        case SYS_semop:
            break;
        case SYS_semctl:
            break;
        case SYS_shmdt:
            break;
        case SYS_msgget:
            break;
        case SYS_msgsnd:
            break;
        case SYS_msgrcv:
            break;
        case SYS_msgctl:
            break;
        case SYS_fcntl:
        {
            BREAK(_SYS_fcntl(n, params));
        }
        case SYS_flock:
        {
            BREAK(_SYS_flock(n, params));
        }
        case SYS_fsync:
        {
            BREAK(_SYS_fsync(n, params));
        }
        case SYS_fdatasync:
        {
            BREAK(_SYS_fdatasync(n, params));
        }
        case SYS_truncate:
        {
            BREAK(_SYS_truncate(n, params));
        }
        case SYS_ftruncate:
        {
            BREAK(_SYS_ftruncate(n, params));
        }
        case SYS_getdents:
            break;
        case SYS_getcwd:
        {
            BREAK(_SYS_getcwd(n, params));
        }
        case SYS_chdir:
        {
            BREAK(_SYS_chdir(n, params));
        }
        case SYS_fchdir:
        {
            BREAK(_SYS_fchdir(n, params));
        }
        case SYS_rename:
        {
            BREAK(_SYS_rename(n, params));
        }
        case SYS_mkdir:
        {
            BREAK(_SYS_mkdir(n, params));
        }
        case SYS_rmdir:
        {
            BREAK(_SYS_rmdir(n, params));
        }
        case SYS_creat:
        {
            BREAK(_SYS_creat(n, params));
        }
        case SYS_link:
        {
            BREAK(_SYS_link(n, params));
        }
        case SYS_unlink:
        {
            BREAK(_SYS_unlink(n, params));
        }
        case SYS_symlink:
        {
            BREAK(_SYS_symlink(n, params));
        }
        case SYS_readlink:
        {
            BREAK(_SYS_readlink(n, params));
        }
        case SYS_chmod:
        {
            BREAK(_SYS_chmod(n, params));
        }
        case SYS_fchmod:
        {
            BREAK(_SYS_fchmod(n, params));
        }
        case SYS_chown:
        {
            BREAK(_SYS_chown(n, params));
        }
        case SYS_fchown:
        {
            BREAK(_SYS_fchown(n, params));
        }
        case SYS_fchownat:
        {
            BREAK(_SYS_fchownat(n, params));
        }
        case SYS_lchown:
        {
            BREAK(_SYS_lchown(n, params));
        }
        case SYS_umask:
        {
            BREAK(_SYS_umask(n, params));
        }
        case SYS_gettimeofday:
        {
            BREAK(_SYS_gettimeofday(n, params));
        }
        case SYS_getrlimit:
            break;
        case SYS_getrusage:
        {
            BREAK(_SYS_getrusage(n, params));
        }
        case SYS_sysinfo:
        {
            BREAK(_SYS_sysinfo(n, params));
        }
        case SYS_times:
        {
            BREAK(_SYS_times(n, params, process));
        }
        case SYS_ptrace:
            break;
        case SYS_syslog:
        {
            BREAK(_SYS_syslog(n, params));
        }
        case SYS_setpgid:
        {
            BREAK(_SYS_setpgid(n, params, thread));
        }
        case SYS_getpgid:
        {
            BREAK(_SYS_getpgid(n, params, thread));
        }
        case SYS_getpgrp:
        {
            BREAK(_SYS_getpgrp(n, params, process, thread));
        }
        case SYS_getppid:
        {
            BREAK(_SYS_getppid(n, params));
        }
        case SYS_getsid:
        {
            BREAK(_SYS_getsid(n, params));
        }
        case SYS_setsid:
        {
            BREAK(_SYS_setsid(n, params));
        }
        case SYS_getgroups:
        {
            BREAK(_SYS_getgroups(n, params));
        }
        case SYS_setgroups:
        {
            BREAK(_SYS_setgroups(n, params));
        }
        case SYS_getuid:
        {
            BREAK(_SYS_getuid(n, params));
        }
        case SYS_setuid:
        {
            BREAK(_SYS_setuid(n, params));
        }
        case SYS_getgid:
        {
            BREAK(_SYS_getgid(n, params));
        }
        case SYS_setgid:
        {
            BREAK(_SYS_setgid(n, params));
        }
        case SYS_geteuid:
        {
            BREAK(_SYS_geteuid(n, params));
        }
        case SYS_getegid:
        {
            BREAK(_SYS_getegid(n, params));
        }
        case SYS_setreuid:
        {
            BREAK(_SYS_setreuid(n, params));
        }
        case SYS_setregid:
        {
            BREAK(_SYS_setregid(n, params));
        }
        case SYS_setresuid:
        {
            BREAK(_SYS_setresuid(n, params));
        }
        case SYS_getresuid:
        {
            BREAK(_SYS_getresuid(n, params));
        }
        case SYS_setresgid:
        {
            BREAK(_SYS_setresgid(n, params));
        }
        case SYS_getresgid:
        {
            BREAK(_SYS_getresgid(n, params));
        }
        case SYS_setfsuid:
        {
            BREAK(_SYS_setfsuid(n, params));
        }
        case SYS_setfsgid:
        {
            BREAK(_SYS_setfsgid(n, params));
        }
        case SYS_capget:
            break;
        case SYS_capset:
            break;
        case SYS_rt_sigpending:
        {
            BREAK(_SYS_rt_sigpending(n, params));
        }
        case SYS_rt_sigtimedwait:
            break;
        case SYS_rt_sigqueueinfo:
            break;
        case SYS_rt_sigsuspend:
            break;
        case SYS_sigaltstack:
        {
            BREAK(_SYS_sigaltstack(n, params));
        }
        case SYS_utime:
            break;
        case SYS_mknod:
        {
            BREAK(_SYS_mknod(n, params));
        }
        case SYS_uselib:
            break;
        case SYS_personality:
            break;
        case SYS_ustat:
            break;
        case SYS_statfs:
        {
            BREAK(_SYS_statfs(n, params));
        }
        case SYS_fstatfs:
        {
            BREAK(_SYS_fstatfs(n, params));
        }
        case SYS_sysfs:
            break;
        case SYS_getpriority:
            break;
        case SYS_setpriority:
            break;
        case SYS_sched_setparam:
        {
            BREAK(_SYS_sched_setparam(n, params));
        }
        case SYS_sched_getparam:
        {
            BREAK(_SYS_sched_getparam(n, params));
        }
        case SYS_sched_setscheduler:
        {
            BREAK(_SYS_sched_setscheduler(n, params));
        }
        case SYS_sched_getscheduler:
        {
            BREAK(_SYS_sched_getscheduler(n, params));
        }
        case SYS_sched_get_priority_max:
        {
            BREAK(_SYS_sched_get_priority_max(n, params));
        }
        case SYS_sched_get_priority_min:
        {
            BREAK(_SYS_sched_get_priority_min(n, params));
        }
        case SYS_sched_rr_get_interval:
            break;
        case SYS_mlock:
        {
            BREAK(_SYS_mlock(n, params));
        }
        case SYS_munlock:
            break;
        case SYS_mlockall:
            break;
        case SYS_munlockall:
            break;
        case SYS_vhangup:
            break;
        case SYS_modify_ldt:
            break;
        case SYS_pivot_root:
            break;
        case SYS__sysctl:
            break;
        case SYS_prctl:
        {
            BREAK(_SYS_prctl(n, params));
        }
        case SYS_arch_prctl:
        {
            /* this is handled in myst_syscall() */
            break;
        }
        case SYS_adjtimex:
            break;
        case SYS_setrlimit:
            break;
        case SYS_chroot:
            break;
        case SYS_sync:
        {
            BREAK(_SYS_sync(n, params));
        }
        case SYS_acct:
            break;
        case SYS_settimeofday:
            break;
        case SYS_mount:
        {
            BREAK(_SYS_mount(n, params));
        }
        case SYS_umount2:
        {
            BREAK(_SYS_umount2(n, params));
        }
        case SYS_swapon:
            break;
        case SYS_swapoff:
            break;
        case SYS_reboot:
            break;
        case SYS_sethostname:
        {
            BREAK(_SYS_sethostname(n, params));
        }
        case SYS_setdomainname:
            break;
        case SYS_iopl:
            break;
        case SYS_ioperm:
            break;
        case SYS_create_module:
            break;
        case SYS_init_module:
            break;
        case SYS_delete_module:
            break;
        case SYS_get_kernel_syms:
            break;
        case SYS_query_module:
            break;
        case SYS_quotactl:
            break;
        case SYS_nfsservctl:
            break;
        case SYS_getpmsg:
            break;
        case SYS_putpmsg:
            break;
        case SYS_afs_syscall:
            break;
        case SYS_tuxcall:
            break;
        case SYS_security:
            break;
        case SYS_gettid:
        {
            BREAK(_SYS_gettid(n, params));
        }
        case SYS_readahead:
            break;
        case SYS_setxattr:
            break;
        case SYS_lsetxattr:
            break;
        case SYS_fsetxattr:
        {
            BREAK(_SYS_fsetxattr(n, params));
        }
        case SYS_getxattr:
            break;
        case SYS_lgetxattr:
            break;
        case SYS_fgetxattr:
            break;
        case SYS_listxattr:
            break;
        case SYS_llistxattr:
            break;
        case SYS_flistxattr:
            break;
        case SYS_removexattr:
            break;
        case SYS_lremovexattr:
            break;
        case SYS_fremovexattr:
            break;
        case SYS_tkill:
        {
            BREAK(_SYS_tkill(n, params, process));
        }
        case SYS_time:
        {
            BREAK(_SYS_time(n, params));
        }
        case SYS_futex:
        {
            BREAK(_SYS_futex(n, params));
        }
        case SYS_sched_setaffinity:
        {
            BREAK(_SYS_sched_setaffinity(n, params));
        }
        case SYS_sched_getaffinity:
        {
            BREAK(_SYS_sched_getaffinity(n, params));
        }
        case SYS_set_thread_area:
        {
            BREAK(_SYS_set_thread_area(
                n,
                params,
                &crt_td,
                target_td,
                thread,
                &_set_thread_area_called));
        }
        case SYS_io_setup:
            break;
        case SYS_io_destroy:
            break;
        case SYS_io_getevents:
            break;
        case SYS_io_submit:
            break;
        case SYS_io_cancel:
            break;
        case SYS_get_thread_area:
            break;
        case SYS_lookup_dcookie:
            break;
        case SYS_epoll_create:
        {
            BREAK(_SYS_epoll_create(n, params));
        }
        case SYS_epoll_ctl_old:
            break;
        case SYS_epoll_wait_old:
            break;
        case SYS_remap_file_pages:
            break;
        case SYS_getdents64:
        {
            BREAK(_SYS_getdents64(n, params));
        }
        case SYS_set_tid_address:
        {
            BREAK(_SYS_set_tid_address(n, params));
        }
        case SYS_restart_syscall:
            break;
        case SYS_semtimedop:
            break;
        case SYS_fadvise64:
        {
            BREAK(_SYS_fadvise64(n, params));
        }
        case SYS_timer_create:
            break;
        case SYS_timer_settime:
            break;
        case SYS_timer_gettime:
            break;
        case SYS_timer_getoverrun:
            break;
        case SYS_timer_delete:
            break;
        case SYS_clock_settime:
        {
            BREAK(_SYS_clock_settime(n, params));
        }
        case SYS_clock_gettime:
        {
            /* this is handled in myst_syscall() */
            break;
        }
        case SYS_clock_getres:
        {
            BREAK(_SYS_clock_getres(n, params));
        }
        case SYS_clock_nanosleep:
            break;
        case SYS_epoll_wait:
        {
            BREAK(_SYS_epoll_wait(n, params));
        }
        case SYS_epoll_ctl:
        {
            BREAK(_SYS_epoll_ctl(n, params));
        }
        case SYS_tgkill:
        {
            BREAK(_SYS_tgkill(n, params));
        }
        case SYS_utimes:
            break;
        case SYS_vserver:
            break;
        case SYS_mbind:
        {
            BREAK(_SYS_mbind(n, params));
        }
        case SYS_set_mempolicy:
            break;
        case SYS_get_mempolicy:
            break;
        case SYS_mq_open:
            break;
        case SYS_mq_unlink:
            break;
        case SYS_mq_timedsend:
            break;
        case SYS_mq_timedreceive:
            break;
        case SYS_mq_notify:
            break;
        case SYS_mq_getsetattr:
            break;
        case SYS_kexec_load:
            break;
        case SYS_waitid:
        {
            BREAK(_SYS_waitid(n, params));
        }
        case SYS_add_key:
            break;
        case SYS_request_key:
            break;
        case SYS_keyctl:
            break;
        case SYS_ioprio_set:
            break;
        case SYS_ioprio_get:
            break;
        case SYS_inotify_init:
        {
            BREAK(_SYS_inotify_init(n, params));
        }
        case SYS_inotify_add_watch:
        {
            BREAK(_SYS_inotify_add_watch(n, params));
        }
        case SYS_inotify_rm_watch:
        {
            BREAK(_SYS_inotify_rm_watch(n, params));
        }
        case SYS_migrate_pages:
            break;
        case SYS_openat:
        {
            BREAK(_SYS_openat(n, params));
        }
        case SYS_mkdirat:
        {
            BREAK(_SYS_mkdirat(n, params, process));
        }
        case SYS_mknodat:
            break;
        case SYS_futimesat:
        {
            BREAK(_SYS_futimesat(n, params));
        }
        case SYS_newfstatat:
        {
            BREAK(_SYS_newfstatat(n, params));
        }
        case SYS_unlinkat:
        {
            BREAK(_SYS_unlinkat(n, params));
        }
        case SYS_renameat:
        {
            BREAK(_SYS_renameat(n, params));
        }
        case SYS_linkat:
        {
            BREAK(_SYS_linkat(n, params));
        }
        case SYS_symlinkat:
        {
            BREAK(_SYS_symlinkat(n, params));
        }
        case SYS_readlinkat:
        {
            BREAK(_SYS_readlinkat(n, params));
        }
        case SYS_fchmodat:
        {
            BREAK(_SYS_fchmodat(n, params));
        }
        case SYS_faccessat:
        {
            BREAK(_SYS_faccessat(n, params));
        }
        case SYS_pselect6:
            break;
        case SYS_ppoll:
        {
            BREAK(_SYS_ppoll(n, params, process));
        }
        case SYS_unshare:
            break;
        case SYS_set_robust_list:
        {
            BREAK(_SYS_set_robust_list(n, params));
        }
        case SYS_get_robust_list:
        {
            BREAK(_SYS_get_robust_list(n, params));
        }
        case SYS_splice:
            break;
        case SYS_tee:
            break;
        case SYS_sync_file_range:
            break;
        case SYS_vmsplice:
            break;
        case SYS_move_pages:
            break;
        case SYS_utimensat:
        {
            BREAK(_SYS_utimensat(n, params));
        }
        case SYS_epoll_pwait:
        {
            BREAK(_SYS_epoll_pwait(n, params));
        }
        case SYS_signalfd:
            break;
        case SYS_timerfd_create:
            break;
        case SYS_eventfd:
            break;
        case SYS_fallocate:
        {
            BREAK(_SYS_fallocate(n, params));
        }
        case SYS_timerfd_settime:
            break;
        case SYS_timerfd_gettime:
            break;
        case SYS_accept4:
        {
            BREAK(_SYS_accept4(n, params));
        }
        case SYS_signalfd4:
            break;
        case SYS_eventfd2:
        {
            BREAK(_SYS_eventfd2(n, params));
        }
        case SYS_epoll_create1:
        {
            BREAK(_SYS_epoll_create1(n, params));
        }
        case SYS_pipe2:
        {
            BREAK(_SYS_pipe2(n, params));
        }
        case SYS_inotify_init1:
        {
            BREAK(_SYS_inotify_init1(n, params));
        }
        case SYS_preadv:
        {
            BREAK(_SYS_preadv(n, params));
        }
        case SYS_pwritev:
        {
            BREAK(_SYS_pwritev(n, params));
        }
        case SYS_rt_tgsigqueueinfo:
            break;
        case SYS_perf_event_open:
            break;
        case SYS_recvmmsg:
        {
            BREAK(_SYS_recvmmsg(n, params));
        }
        case SYS_fanotify_init:
            break;
        case SYS_fanotify_mark:
            break;
        case SYS_prlimit64:
        {
            BREAK(_SYS_prlimit64(n, params));
        }
        case SYS_name_to_handle_at:
            break;
        case SYS_open_by_handle_at:
            break;
        case SYS_clock_adjtime:
            break;
        case SYS_syncfs:
            break;
        case SYS_sendmmsg:
        {
            BREAK(_SYS_sendmmsg(n, params, thread));
        }
        case SYS_setns:
            break;
        case SYS_getcpu:
        {
            BREAK(_SYS_getcpu(n, params));
        }
        case SYS_process_vm_readv:
            break;
        case SYS_process_vm_writev:
            break;
        case SYS_kcmp:
            break;
        case SYS_finit_module:
            break;
        case SYS_sched_setattr:
            break;
        case SYS_sched_getattr:
            break;
        case SYS_renameat2:
            break;
        case SYS_seccomp:
            break;
        case SYS_getrandom:
        {
            BREAK(_SYS_getrandom(n, params));
        }
        case SYS_memfd_create:
            break;
        case SYS_kexec_file_load:
            break;
        case SYS_bpf:
            break;
        case SYS_execveat:
        {
            BREAK(_SYS_execveat(n, params, thread, args));
        }
        case SYS_userfaultfd:
            break;
        case SYS_membarrier:
        {
            BREAK(_SYS_membarrier(n, params));
        }
        case SYS_mlock2:
            break;
        case SYS_copy_file_range:
        {
            BREAK(_SYS_copy_file_range(n, params));
        }
        case SYS_preadv2:
        {
            BREAK(_SYS_preadv2(n, params));
        }
        case SYS_pwritev2:
        {
            BREAK(_SYS_pwritev2(n, params));
        }
        case SYS_pkey_mprotect:
            break;
        case SYS_pkey_alloc:
            break;
        case SYS_pkey_free:
            break;
        case SYS_statx:
            break;
        case SYS_io_pgetevents:
            break;
        case SYS_rseq:
            break;
        case SYS_bind:
        {
            BREAK(_SYS_bind(n, params));
        }
        case SYS_connect:
        {
            BREAK(_SYS_connect(n, params));
        }
        case SYS_recvfrom:
        {
            BREAK(_SYS_recvfrom(n, params));
        }
        case SYS_sendto:
        {
            BREAK(_SYS_sendto(n, params, thread));
        }
        case SYS_socket:
        {
            BREAK(_SYS_socket(n, params));
        }
        case SYS_accept:
        {
            BREAK(_SYS_accept(n, params));
        }
        case SYS_sendmsg:
        {
            BREAK(_SYS_sendmsg(n, params, thread));
        }
        case SYS_recvmsg:
        {
            BREAK(_SYS_recvmsg(n, params));
        }
        case SYS_shutdown:
        {
            BREAK(_SYS_shutdown(n, params));
        }
        case SYS_listen:
        {
            BREAK(_SYS_listen(n, params));
        }
        case SYS_getsockname:
        {
            BREAK(_SYS_getsockname(n, params));
        }
        case SYS_getpeername:
        {
            BREAK(_SYS_getpeername(n, params));
        }
        case SYS_socketpair:
        {
            BREAK(_SYS_socketpair(n, params));
        }
        case SYS_setsockopt:
        {
            BREAK(_SYS_setsockopt(n, params));
        }
        case SYS_getsockopt:
        {
            BREAK(_SYS_getsockopt(n, params));
        }
        case SYS_sendfile:
        {
            BREAK(_SYS_sendfile(n, params));
        }
        /* forward Open Enclave extensions to the target */
        case SYS_myst_oe_get_report_v2:
        case SYS_myst_oe_free_report:
        case SYS_myst_oe_get_target_info_v2:
        case SYS_myst_oe_free_target_info:
        case SYS_myst_oe_parse_report:
        case SYS_myst_oe_verify_report:
        case SYS_myst_oe_get_seal_key_by_policy_v2:
        case SYS_myst_oe_get_public_key_by_policy:
        case SYS_myst_oe_get_public_key:
        case SYS_myst_oe_get_private_key_by_policy:
        case SYS_myst_oe_get_private_key:
        case SYS_myst_oe_free_key:
        case SYS_myst_oe_get_seal_key_v2:
        case SYS_myst_oe_free_seal_key:
        case SYS_myst_oe_generate_attestation_certificate:
        case SYS_myst_oe_free_attestation_certificate:
        case SYS_myst_oe_verify_attestation_certificate:
        case SYS_myst_oe_result_str:
        case SYS_myst_oe_get_enclave_start_address:
        case SYS_myst_oe_get_enclave_base_address:
        {
            _strace(n, "forwarded");
            BREAK(_return(n, _forward_syscall(n, params)));
        }
        default:
        {
            if (__myst_kernel_args.unhandled_syscall_enosys == true)
                syscall_ret = -ENOSYS;
            else
                myst_panic("unknown syscall: %s(): %ld", _syscall_str(n), n);
        }
    }

    if (__myst_kernel_args.unhandled_syscall_enosys == true)
        syscall_ret = -ENOSYS;
    else
        myst_panic("unhandled syscall: %s()", _syscall_str(n));

done:

    /* ---------- running target thread descriptor ---------- */

    /* Process signals pending for this thread, if there is any,
     * before switching back to the C-runtime thread descriptor to
     * ensure running the signal processing code with the kernel
     * thread descriptor. */
    myst_signal_process(thread);

    /* the C-runtime must execute on its own thread descriptor */
    if (crt_td)
        myst_set_fsbase(crt_td);

    myst_times_leave_kernel(n);

    return syscall_ret;
}

long myst_syscall(long n, long params[6])
{
    long ret;
    uint64_t rsp;
    myst_kstack_t* kstack;
    void* saved_fs;
    void* base_fs;

    /* At this point, we cannot be sure about what FS is using (determined
     * by _syscall). To ensure using the kernel FS (same as OE FS) when calling
     * functions that could come across the OE layer (e.g., making an OCALL),
     * we temporarily switch to the kernel FS if it has user value before
     * calling the function and restore when the function returns. */
    asm("mov %%fs:0, %0" : "=r"(saved_fs));
    asm("mov %%gs:0, %0" : "=r"(base_fs));

    // Call myst_syscall_clock_gettime() upfront to avoid triggering the
    // overhead of myst_times_enter_kernel() and myst_times_leave_kernel(),
    // which also read the clock.
    if (n == SYS_clock_gettime)
    {
        clockid_t clk_id = (clockid_t)params[0];
        struct timespec* tp = (struct timespec*)params[1];
        /* No need to switch FS as myst_syscall_clock_gettime does not make
         * OCALLs */
        return myst_syscall_clock_gettime(clk_id, tp);
    }

    // Call myst_syscall_arch_prctl() upfront since it can only be performed
    // on the caller's stack and before the fsbase is changed by the prologue
    // code that follows.
    if (n == SYS_arch_prctl)
    {
        int code = (int)params[0];
        unsigned long* addr = (unsigned long*)params[1];
        /* No need to switch FS as myst_syscall_arch_prctl does not make
         * OCALLs */
        return myst_syscall_arch_prctl(code, addr);
    }

    /* Switch FS before myst_get_kstack, which could make OCALLs because of
     * myst_mmap and myst_mprotect */
    if (saved_fs != base_fs)
        myst_set_fsbase(base_fs);

    if (!(kstack = myst_get_kstack()))
        myst_panic("no more kernel stacks");

    /* Restore FS */
    if (saved_fs != base_fs)
        myst_set_fsbase(saved_fs);

    // Get the user rsp before switching to the kernel stack
    asm volatile("mov %%rsp, %0" : "=r"(rsp));

    syscall_args_t args = {
        .n = n, .params = params, .kstack = kstack, .user_rsp = rsp};
    ret = myst_call_on_stack(myst_kstack_end(kstack), _syscall, &args);

    myst_put_kstack(kstack);

    return ret;
}

/*
**==============================================================================
**
** syscalls
**
**==============================================================================
*/

static myst_spinlock_t _get_time_lock = MYST_SPINLOCK_INITIALIZER;
static myst_spinlock_t _set_time_lock = MYST_SPINLOCK_INITIALIZER;

long myst_syscall_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    if (!tp)
        return -EFAULT;

    /* validate parameter is writable */
    memset(tp, 0, sizeof(*tp));

    if (clk_id < 0)
    {
        // ATTN: Support Dynamic clocks
        if (IS_DYNAMIC_CLOCK(clk_id))
            return -ENOTSUP;
        else
            return myst_times_get_cpu_clock_time(clk_id, tp);
    }

    if (clk_id == CLOCK_PROCESS_CPUTIME_ID)
    {
        long nanoseconds = myst_times_process_time(myst_process_self());
        tp->tv_sec = nanoseconds / NANO_IN_SECOND;
        tp->tv_nsec = nanoseconds % NANO_IN_SECOND;
        return 0;
    }
    if (clk_id == CLOCK_THREAD_CPUTIME_ID)
    {
        long nanoseconds = myst_times_thread_time(myst_thread_self());
        tp->tv_sec = nanoseconds / NANO_IN_SECOND;
        tp->tv_nsec = nanoseconds % NANO_IN_SECOND;
        return 0;
    }

    myst_spin_lock(&_get_time_lock);
    long params[6] = {(long)clk_id, (long)tp};
    long ret = myst_tcall(MYST_TCALL_CLOCK_GETTIME, params);
    myst_spin_unlock(&_get_time_lock);
    return ret;
}

long myst_syscall_clock_settime(clockid_t clk_id, struct timespec* tp)
{
    long params[6] = {(long)clk_id, (long)tp};

    /* validate parameter is writable */
    memset(tp, 0, sizeof(*tp));

    myst_spin_lock(&_set_time_lock);
    long ret = myst_tcall(MYST_TCALL_CLOCK_SETTIME, params);
    myst_spin_unlock(&_set_time_lock);
    return ret;
}

long myst_syscall_gettimeofday(struct timeval* tv, struct timezone* tz)
{
    (void)tz;
    struct timespec tp = {0};
    if (tv == NULL)
        return 0;

    long ret = myst_syscall_clock_gettime(CLOCK_REALTIME, &tp);
    if (ret == 0)
    {
        tv->tv_sec = tp.tv_sec;
        tv->tv_usec = tp.tv_nsec / 1000;
    }
    return ret;
}

long myst_syscall_time(time_t* tloc)
{
    struct timespec tp = {0};
    long ret = myst_syscall_clock_gettime(CLOCK_REALTIME, &tp);
    if (ret == 0)
    {
        if (tloc != NULL)
            *tloc = tp.tv_sec;
        ret = tp.tv_sec;
    }
    return ret;
}

long myst_syscall_clock_getres(clockid_t clk_id, struct timespec* res)
{
    long params[6] = {(long)clk_id, (long)res};

    if (res && myst_is_bad_addr_read_write(res, sizeof(struct timespec)))
        return -EFAULT;
    else if (res == NULL)
        return -EINVAL;

    long ret = myst_tcall(MYST_TCALL_CLOCK_GETRES, params);
    return ret;
}

long myst_syscall_tgkill(int tgid, int tid, int sig)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* target = myst_find_thread(tid);
    siginfo_t* siginfo;

    if (target == NULL)
        ERAISE(-ESRCH);

    // Only allow a thread to kill other threads in the same group.
    if (tgid != thread->process->pid)
        ERAISE(-EINVAL);

    if (!(siginfo = calloc(1, sizeof(siginfo_t))))
        ERAISE(-ENOMEM);

    siginfo->si_code = SI_TKILL;
    siginfo->si_signo = sig;
    myst_signal_deliver(target, sig, siginfo);

done:
    return ret;
}

static long _myst_send_kill(myst_process_t* process, int signum)
{
    long ret = 0;
    siginfo_t* siginfo;

    if (!(siginfo = calloc(1, sizeof(siginfo_t))))
        ERAISE(-ENOMEM);

    siginfo->si_code = SI_USER;
    siginfo->si_signo = signum;
    siginfo->si_pid = process->pid;
    siginfo->si_uid = process->main_process_thread->euid;

    ret = myst_signal_deliver(process->main_process_thread, signum, siginfo);

done:
    return ret;
}

long myst_syscall_kill(int pid, int signum)
{
    long ret = 0;
    myst_process_t* process_self = myst_process_self();
    myst_process_t* process = myst_main_process;
    bool delivered_any = false;

    if ((pid < -1) && (process_self->pgid == -pid))
    {
        delivered_any = true;
        if (signum != 0)
        {
            ECHECK(_myst_send_kill(process_self, signum));
            ECHECK(myst_signal_process(process_self->main_process_thread));
        }
    }

    myst_spin_lock(&myst_process_list_lock);

    while (process)
    {
        // If pid > 0 send signal to specific process.
        if ((pid > 0) && (process->pid == pid))
        {
            delivered_any = true;
            if (signum != 0)
                ret = _myst_send_kill(process, signum);
            break;
        }

        // If pid == 0, send to all processes in process group
        else if (
            (pid == 0) && (process->pid != process_self->pid) &&
            (process->pgid == process_self->pgid))
        {
            delivered_any = true;
            if (signum == 0)
                break;
            ECHECK(_myst_send_kill(process, signum));
        }

        // if pid == -1 send to all processes
        else if (pid == -1)
        {
            delivered_any = true;
            if (signum == 0)
                break;
            ECHECK(_myst_send_kill(process, signum));
        }

        // if pid < -1 send to processes in specific process group
        else if (
            ((pid < -1) && (process->pgid == -pid)) &&
            (process != process_self))
        {
            delivered_any = true;
            if (signum == 0)
                break;
            ECHECK(_myst_send_kill(process, signum));
        }

        process = process->next_process;
    }

    // Did we finally find any processes to deliver signal to?
    if (!delivered_any)
        ERAISE(-ESRCH);

done:
    myst_spin_unlock(&myst_process_list_lock);

    return ret;
}

long myst_syscall_isatty(int fd)
{
    long params[6] = {(long)fd};
    return myst_tcall(MYST_TCALL_ISATTY, params);
}

long myst_syscall_add_symbol_file(
    const char* path,
    const void* text,
    size_t text_size)
{
    long ret = 0;
    void* file_data = NULL;
    size_t file_size;
    long params[6] = {0};

    ECHECK(myst_load_file(path, &file_data, &file_size));

    params[0] = (long)file_data;
    params[1] = (long)file_size;
    params[2] = (long)text;
    params[3] = (long)text_size;
    params[4] = (long)path;

    ECHECK(myst_tcall(MYST_TCALL_ADD_SYMBOL_FILE, params));

done:

    if (file_data)
        free(file_data);

    return ret;
}

long myst_syscall_load_symbols(void)
{
    long params[6] = {0};
    return myst_tcall(MYST_TCALL_LOAD_SYMBOLS, params);
}

long myst_syscall_unload_symbols(void)
{
    long params[6] = {0};
    return myst_tcall(MYST_TCALL_UNLOAD_SYMBOLS, params);
}

long myst_syscall_pause(void)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();
    // Set futex unavilable. This is to make sure the futex which was made
    // available by signals delivered before calling pause won't affect the
    // current call. In other words, this calling of pause should only be woken
    // by future signals.
    __sync_val_compare_and_swap(&thread->pause_futex, 1, 0);
    while (1)
    {
        // Is the futex available?
        if (__sync_val_compare_and_swap(&thread->pause_futex, 1, 0))
        {
            ret = -EINTR;
            break;
        }

        // Futex is not available, wait.
        ret = myst_futex_wait(
            &thread->pause_futex, 0, NULL, FUTEX_BITSET_MATCH_ANY);
        if (ret != 0 && ret != -EAGAIN)
            ERAISE(ret);
    }
done:
    return ret;
}
