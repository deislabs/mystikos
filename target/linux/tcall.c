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

#include <libos/eraise.h>
#include <libos/syscall.h>
#include <libos/syscallext.h>
#include <libos/tcall.h>
#include <libos/thread.h>

#include "debugmalloc.h"

#ifdef LIBOS_DEBUG_MALLOC
#define MALLOC libos_debug_malloc
#define CALLOC libos_debug_calloc
#define REALLOC libos_debug_realloc
#define MEMALIGN libos_debug_memalign
#define FREE libos_debug_free
#else
#define MALLOC malloc
#define CALLOC calloc
#define REALLOC realloc
#define MEMALIGN memalign
#define FREE free
#endif

libos_run_thread_t __libos_run_thread;

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

static long _tcall_allocate(
    void* ptr,
    size_t alignment,
    size_t size,
    int clear,
    void** new_ptr)
{
    int ret = 0;

    if (!new_ptr)
        ERAISE(-EINVAL);

    if (ptr)
    {
        if (clear || alignment)
            ERAISE(-EINVAL);

        if (size == 0)
        {
            // FREE(ptr);
            *new_ptr = NULL;
            goto done;
        }

        if (!(*new_ptr = REALLOC(ptr, size)))
            ERAISE(-ENOMEM);
    }
    else if (alignment)
    {
        if (clear)
            ERAISE(-EINVAL);

        if (size == 0)
        {
            *new_ptr = NULL;
            goto done;
        }

        if (!(*new_ptr = MEMALIGN(alignment, size)))
            ERAISE(-ENOMEM);
    }
    else
    {
        if (size == 0)
        {
            *new_ptr = NULL;
            goto done;
        }

        if (clear)
        {
            if (!(*new_ptr = CALLOC(size, 1)))
                ERAISE(-ENOMEM);
        }
        else
        {
            if (!(*new_ptr = MALLOC(size)))
                ERAISE(-ENOMEM);
        }
    }

done:
    return ret;
}

static long _tcall_deallocate(void* ptr)
{
    if (ptr)
        FREE(ptr);

    return 0;
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

static long _tcall_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    return syscall(SYS_clock_gettime, clk_id, tp);
}

static long _isatty(int fd)
{
    int ret = isatty(fd);

    if (ret < 0)
        ret = -errno;

    return ret;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_add_symbol_file(
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
LIBOS_WEAK
long libos_tcall_load_symbols(void)
{
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_unload_symbols(void)
{
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_create_thread(uint64_t cookie)
{
    (void)cookie;
    assert("linux: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

LIBOS_WEAK
long libos_tcall_export_file(const char* path, const void* data, size_t size)
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
    return libos_syscall6(n, x1, x2, x3, x4, x5, x6);
}

long libos_target_stat(libos_target_stat_t* buf)
{
    long ret = 0;

    if (!buf)
        ERAISE(-EINVAL);

    memset(buf, 0, sizeof(libos_target_stat_t));

    /* nothing to provide */

done:
    return ret;
}

long libos_tcall(long n, long params[6])
{
    long ret = 0;
    const long x1 = params[0];
    const long x2 = params[1];
    const long x3 = params[2];
    const long x4 = params[3];
    const long x5 = params[4];
    const long x6 = params[5];

    // printf("libos_tcall(): n=%ld\n", n);

    switch (n)
    {
        case LIBOS_TCALL_RANDOM:
        {
            return _tcall_random((void*)x1, (size_t)x2);
        }
        case LIBOS_TCALL_ALLOCATE:
        {
            void* ptr = (void*)x1;
            size_t alignment = (size_t)x2;
            size_t size = (size_t)x3;
            int clear = (int)x4;
            void** new_ptr = (void**)x5;
            return _tcall_allocate(ptr, alignment, size, clear, new_ptr);
        }
        case LIBOS_TCALL_DEALLOCATE:
        {
            void* ptr = (void*)x1;
            return _tcall_deallocate(ptr);
        }
        case LIBOS_TCALL_VSNPRINTF:
        {
            char* str = (char*)x1;
            size_t size = (size_t)x2;
            const char* format = (const char*)x3;
            va_list* ap = (va_list*)x4;
            return _tcall_vsnprintf(str, size, format, *ap);
        }
        case LIBOS_TCALL_WRITE_CONSOLE:
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
        case LIBOS_TCALL_CLOCK_GETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return _tcall_clock_gettime(clk_id, tp);
        }
        case LIBOS_TCALL_ISATTY:
        {
            int fd = (int)x1;
            return _isatty(fd);
        }
        case LIBOS_TCALL_ADD_SYMBOL_FILE:
        {
            const void* file_data = (const void*)x1;
            size_t file_size = (size_t)x2;
            const void* text = (const void*)x3;
            size_t text_size = (size_t)x4;
            return libos_tcall_add_symbol_file(
                file_data, file_size, text, text_size);
        }
        case LIBOS_TCALL_LOAD_SYMBOLS:
        {
            return libos_tcall_load_symbols();
        }
        case LIBOS_TCALL_UNLOAD_SYMBOLS:
        {
            return libos_tcall_unload_symbols();
        }
        case LIBOS_TCALL_CREATE_THREAD:
        {
            uint64_t cookie = (uint64_t)x1;
            return libos_tcall_create_thread(cookie);
        }
        case LIBOS_TCALL_WAIT:
        {
            uint64_t event = (uint64_t)x1;
            const struct timespec* timeout = (const struct timespec*)x2;
            return libos_tcall_wait(event, timeout);
        }
        case LIBOS_TCALL_WAKE:
        {
            uint64_t event = (uint64_t)x1;
            return libos_tcall_wake(event);
        }
        case LIBOS_TCALL_WAKE_WAIT:
        {
            uint64_t waiter_event = (uint64_t)x1;
            uint64_t self_event = (uint64_t)x2;
            const struct timespec* timeout = (const struct timespec*)x3;
            return libos_tcall_wake_wait(waiter_event, self_event, timeout);
        }
        case LIBOS_TCALL_EXPORT_FILE:
        {
            const char* path = (const char*)x1;
            const void* data = (const void*)x2;
            size_t size = (size_t)x3;
            return libos_tcall_export_file(path, data, size);
        }
        case LIBOS_TCALL_SET_RUN_THREAD_FUNCTION:
        {
            libos_run_thread_t function = (libos_run_thread_t)x1;

            if (!function)
                return -EINVAL;

            __libos_run_thread = function;
            return 0;
        }
        case LIBOS_TCALL_TARGET_STAT:
        {
            libos_target_stat_t* buf = (libos_target_stat_t*)x1;
            return libos_target_stat(buf);
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
        case SYS_read:
        case SYS_write:
        case SYS_close:
        case SYS_poll:
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
        {
            return _forward_syscall(n, x1, x2, x3, x4, x5, x6);
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}
