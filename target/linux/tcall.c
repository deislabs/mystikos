// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/fssig.h>
#include <myst/luks.h>
#include <myst/sha256.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <oeprivate/rsa.h>

enum _oe_result
{
    OE_OK = 0,
};

myst_run_thread_t __myst_run_thread;

static long _tcall_random(void* data, size_t size)
{
    long ret = 0;
    uint8_t* p = data;
    size_t r = size;

    if (!data)
        ERAISE(-EINVAL);

    if (size == 0)
        goto done;

    while (r)
    {
        long n = syscall(SYS_getrandom, p, r, 0);

        if (n == -EINVAL || n == -EINTR)
            continue;

        if (n < 0)
        {
            ret = r;
            break;
        }

        assert(n <= r);

        r -= (size_t)n;
        p += (size_t)n;
    }

done:
    return ret;
}

static long _tcall_vsnprintf(
    char* str,
    size_t size,
    const char* format,
    va_list ap)
{
    if (!str || !format)
        return -EINVAL;

    long ret = (long)vsnprintf(str, size, format, ap);

    return ret;
}

static long _tcall_clock_getres(clockid_t clk_id, struct timespec* res)
{
    return syscall(SYS_clock_getres, clk_id, res);
}

static long _tcall_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    return syscall(SYS_clock_gettime, clk_id, tp);
}

static long _tcall_clock_settime(clockid_t clk_id, struct timespec* tp)
{
    return syscall(SYS_clock_settime, clk_id, tp);
}

static long _isatty(int fd)
{
    int ret = isatty(fd);

    if (ret < 0)
        ret = -errno;

    return ret;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text,
    size_t text_size)
{
    (void)file_data;
    (void)file_size;
    (void)text;
    (void)text_size;
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_load_symbols(void)
{
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_unload_symbols(void)
{
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_create_thread(uint64_t cookie)
{
    (void)cookie;
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

MYST_WEAK
long myst_tcall_export_file(const char* path, const void* data, size_t size)
{
    (void)path;
    (void)data;
    (void)size;
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* forward system call to Linux */
static long
_forward_syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    return myst_syscall6(n, x1, x2, x3, x4, x5, x6);
}

static long _tcall_target_stat(myst_target_stat_t* buf)
{
    long ret = 0;

    if (!buf)
        ERAISE(-EINVAL);

    memset(buf, 0, sizeof(myst_target_stat_t));

    /* nothing to provide */

done:
    return ret;
}

static __thread uint64_t _tsd;

static long _tcall_set_tsd(uint64_t value)
{
    _tsd = value;

    return 0;
}

static long _tcall_get_tsd(uint64_t* value)
{
    if (!value)
        return -EINVAL;

    *value = _tsd;

    return 0;
}

long myst_tcall_identity(long n, long params[6], uid_t uid, gid_t gid)
{
    long ret = 0;
    const long x1 = params[0];
    const long x2 = params[1];
    const long x3 = params[2];
    const long x4 = params[3];
    const long x5 = params[4];
    const long x6 = params[5];
    uid_t existing_uid, existing_euid, existing_savuid;
    gid_t existing_gid, existing_egid, existing_savgid;

    ret =
        syscall(SYS_getresuid, &existing_uid, &existing_euid, &existing_savuid);
    if (ret != 0)
        return ret;

    ret =
        syscall(SYS_getresgid, &existing_gid, &existing_egid, &existing_savgid);
    if (ret != 0)
        return ret;

    if (existing_egid != gid)
    {
        ret = syscall(SYS_setresgid, -1, gid, -1);
        if (ret != 0)
            return ret;
    }

    if (existing_euid != uid)
    {
        ret = syscall(SYS_setresuid, -1, uid, -1);
        if (ret != 0)
        {
            myst_assume(
                syscall(
                    SYS_setresgid,
                    existing_gid,
                    existing_egid,
                    existing_egid) == 0);
            return ret;
        }
    }

    ret = _forward_syscall(n, x1, x2, x3, x4, x5, x6);

    if (existing_euid != uid)
    {
        myst_assume(
            syscall(
                SYS_setresuid, existing_uid, existing_euid, existing_euid) ==
            0);
    }
    if (existing_egid != gid)
    {
        myst_assume(
            syscall(
                SYS_setresgid, existing_gid, existing_egid, existing_savgid) ==
            0);
    }

    return ret;
}

long myst_tcall(long n, long params[6])
{
    long ret = 0;
    const long x1 = params[0];
    const long x2 = params[1];
    const long x3 = params[2];
    const long x4 = params[3];
    const long x5 = params[4];
    const long x6 = params[5];

    // printf("myst_tcall(): n=%ld\n", n);

    switch (n)
    {
        case MYST_TCALL_RANDOM:
        {
            return _tcall_random((void*)x1, (size_t)x2);
        }
        case MYST_TCALL_VSNPRINTF:
        {
            char* str = (char*)x1;
            size_t size = (size_t)x2;
            const char* format = (const char*)x3;
            va_list* ap = (va_list*)x4;
            return _tcall_vsnprintf(str, size, format, *ap);
        }
        case MYST_TCALL_WRITE_CONSOLE:
        {
            int fd = (int)x1;
            const void* buf = (const void*)x2;
            size_t count = (size_t)x3;
            FILE* stream = NULL;

            if (fd == STDOUT_FILENO)
                stream = stdout;
            else if (fd == STDERR_FILENO)
                stream = stderr;
            else
                return -EINVAL;

            if (fwrite(buf, 1, count, stream) != count)
                return -EIO;

            return (long)count;
        }
        case MYST_TCALL_READ_CONSOLE:
        {
            int fd = (int)x1;
            void* buf = (void*)x2;
            size_t count = (size_t)x3;
            FILE* stream = NULL;

            if (fd == STDOUT_FILENO)
                stream = stdout;
            else if (fd == STDERR_FILENO)
                stream = stderr;
            else
                return -EINVAL;

            if (fread(buf, 1, count, stream) != count)
                return -EIO;

            return (long)count;
        }
        case MYST_TCALL_CLOCK_GETRES:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* res = (struct timespec*)x2;
            return _tcall_clock_getres(clk_id, res);
        }
        case MYST_TCALL_CLOCK_GETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return _tcall_clock_gettime(clk_id, tp);
        }
        case MYST_TCALL_CLOCK_SETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return _tcall_clock_settime(clk_id, tp);
        }
        case MYST_TCALL_ISATTY:
        {
            int fd = (int)x1;
            return _isatty(fd);
        }
        case MYST_TCALL_ADD_SYMBOL_FILE:
        {
            const void* file_data = (const void*)x1;
            size_t file_size = (size_t)x2;
            const void* text = (const void*)x3;
            size_t text_size = (size_t)x4;
            return myst_tcall_add_symbol_file(
                file_data, file_size, text, text_size);
        }
        case MYST_TCALL_LOAD_SYMBOLS:
        {
            return myst_tcall_load_symbols();
        }
        case MYST_TCALL_UNLOAD_SYMBOLS:
        {
            return myst_tcall_unload_symbols();
        }
        case MYST_TCALL_CREATE_THREAD:
        {
            uint64_t cookie = (uint64_t)x1;
            return myst_tcall_create_thread(cookie);
        }
        case MYST_TCALL_WAIT:
        {
            uint64_t event = (uint64_t)x1;
            const struct timespec* timeout = (const struct timespec*)x2;
            return myst_tcall_wait(event, timeout);
        }
        case MYST_TCALL_WAKE:
        {
            uint64_t event = (uint64_t)x1;
            return myst_tcall_wake(event);
        }
        case MYST_TCALL_WAKE_WAIT:
        {
            uint64_t waiter_event = (uint64_t)x1;
            uint64_t self_event = (uint64_t)x2;
            const struct timespec* timeout = (const struct timespec*)x3;
            return myst_tcall_wake_wait(waiter_event, self_event, timeout);
        }
        case MYST_TCALL_EXPORT_FILE:
        {
            const char* path = (const char*)x1;
            const void* data = (const void*)x2;
            size_t size = (size_t)x3;
            return myst_tcall_export_file(path, data, size);
        }
        case MYST_TCALL_SET_RUN_THREAD_FUNCTION:
        {
            myst_run_thread_t function = (myst_run_thread_t)x1;

            if (!function)
                return -EINVAL;

            __myst_run_thread = function;
            return 0;
        }
        case MYST_TCALL_TARGET_STAT:
        {
            myst_target_stat_t* buf = (myst_target_stat_t*)x1;
            return _tcall_target_stat(buf);
        }
        case MYST_TCALL_SET_TSD:
        {
            uint64_t value = (uint64_t)x1;
            return _tcall_set_tsd(value);
        }
        case MYST_TCALL_GET_TSD:
        {
            uint64_t* value = (uint64_t*)x1;
            return _tcall_get_tsd(value);
        }
        case MYST_TCALL_GET_ERRNO_LOCATION:
        {
            static __thread int _errnum;
            int** ptr = (int**)x1;

            if (!ptr)
                return -EINVAL;

            *ptr = &_errnum;
            return 0;
        }
        case MYST_TCALL_POLL_WAKE:
        {
            return myst_tcall_poll_wake();
        }
        case MYST_TCALL_OPEN_BLOCK_DEVICE:
        {
            return myst_open_block_device((const char*)x1, (bool)x2);
        }
        case MYST_TCALL_CLOSE_BLOCK_DEVICE:
        {
            return myst_close_block_device((int)x1);
        }
        case MYST_TCALL_READ_BLOCK_DEVICE:
        {
            return myst_read_block_device(
                (int)x1, (uint64_t)x2, (struct myst_block*)x3, (size_t)x4);
        }
        case MYST_TCALL_WRITE_BLOCK_DEVICE:
        {
            return myst_write_block_device(
                (int)x1,
                (uint64_t)x2,
                (const struct myst_block*)x3,
                (size_t)x4);
        }
        case MYST_TCALL_LUKS_ENCRYPT:
        {
            return myst_luks_encrypt(
                (const luks_phdr_t*)x1,
                (const void*)x2,
                (const uint8_t*)x3,
                (uint8_t*)x4,
                (size_t)x5,
                (uint64_t)x6);
        }
        case MYST_TCALL_LUKS_DECRYPT:
        {
            return myst_luks_decrypt(
                (const luks_phdr_t*)x1,
                (const void*)x2,
                (const uint8_t*)x3,
                (uint8_t*)x4,
                (size_t)x5,
                (uint64_t)x6);
        }
        case MYST_TCALL_SHA256_START:
        {
            return myst_sha256_start((myst_sha256_ctx_t*)x1);
        }
        case MYST_TCALL_SHA256_UPDATE:
        {
            return myst_sha256_update(
                (myst_sha256_ctx_t*)x1, (const void*)x2, (size_t)x3);
        }
        case MYST_TCALL_SHA256_FINISH:
        {
            return myst_sha256_finish(
                (myst_sha256_ctx_t*)x1, (myst_sha256_t*)x2);
        }
        case MYST_TCALL_VERIFY_SIGNATURE:
        {
            long* args = (long*)x1;
            return myst_tcall_verify_signature(
                (const char*)args[0],
                (const uint8_t*)args[1],
                (size_t)args[2],
                (const uint8_t*)args[3],
                (size_t)args[4],
                (const uint8_t*)args[5],
                (size_t)args[6]);
        }
        case MYST_TCALL_LOAD_FSSIG:
        {
            return myst_load_fssig((const char*)x1, (myst_fssig_t*)x2);
        }
        case SYS_ioctl:
        {
            int fd = (int)x1;
            unsigned long request = (unsigned long)x2;
            const int* arg = (const int*)x3;

            /* Map FIONBIO to fcntl() since broken in Open Enclave */
            if (request == FIONBIO)
            {
                long flags;

                if (!arg)
                    return -EINVAL;

                /* Get the access mode and the file status flags */
                flags = _forward_syscall(SYS_fcntl, fd, F_GETFL, 0, 0, 0, 0);

                /* Set to non-blocking or blocking */
                if (*arg)
                    flags = (flags | O_NONBLOCK);
                else
                    flags = (flags & ~O_NONBLOCK);

                return _forward_syscall(SYS_fcntl, fd, F_SETFL, flags, 0, 0, 0);
            }

            return _forward_syscall(n, x1, x2, x3, x4, x5, x6);
        }
        case SYS_poll:
        {
            struct pollfd* fds = (struct pollfd*)x1;
            nfds_t nfds = (nfds_t)x2;
            int timeout = (int)x3;
            return myst_tcall_poll(fds, nfds, timeout);
        }
        case SYS_sched_yield:
        case SYS_fstat:
        case SYS_read:
        case SYS_write:
        case SYS_close:
        case SYS_readv:
        case SYS_writev:
        case SYS_select:
        case SYS_nanosleep:
        case SYS_fcntl:
        case SYS_gettimeofday:
        case SYS_sethostname:
        case SYS_bind:
        case SYS_connect:
        case SYS_recvfrom:
        case SYS_sendfile:
        case SYS_socket:
        case SYS_accept:
        case SYS_accept4:
        case SYS_sendto:
        case SYS_sendmsg:
        case SYS_recvmsg:
        case SYS_shutdown:
        case SYS_listen:
        case SYS_getsockname:
        case SYS_getpeername:
        case SYS_socketpair:
        case SYS_setsockopt:
        case SYS_getsockopt:
        case SYS_fchmod:
        case SYS_access:
        case SYS_dup:
        case SYS_pread64:
        case SYS_pwrite64:
        case SYS_link:
        case SYS_unlink:
        case SYS_mkdir:
        case SYS_rmdir:
        case SYS_getdents64:
        case SYS_rename:
        case SYS_truncate:
        case SYS_ftruncate:
        case SYS_symlink:
        case SYS_lstat:
        case SYS_readlink:
        case SYS_statfs:
        case SYS_fstatfs:
        case SYS_lseek:
        case SYS_sched_setaffinity:
        case SYS_sched_getaffinity:
        case SYS_getcpu:
        {
            return _forward_syscall(n, x1, x2, x3, x4, x5, x6);
        }
        case SYS_open:
        {
            return myst_tcall_identity(n, params, (uid_t)x4, (gid_t)x5);
        }
        case SYS_stat:
        {
            return myst_tcall_identity(n, params, (uid_t)x3, (gid_t)x4);
        }
        case SYS_utimensat:
        {
            return myst_tcall_identity(n, params, (uid_t)x5, (gid_t)x6);
        }
        default:
        {
            fprintf(stderr, "unhandled tcall: %ld\n", n);
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}
