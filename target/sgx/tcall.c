#include <libos/tcall.h>
#include <libos/eraise.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <openenclave/enclave.h>
#include "gencreds.h"

long oe_syscall(
    long n,
    long x1,
    long x2,
    long x3,
    long x4,
    long x5,
    long x6);

static long _tcall_random(void* data, size_t size)
{
    long ret = 0;
    extern oe_result_t oe_random(void* data, size_t size);

    if (!data)
        ERAISE(-EINVAL);

    if (oe_random(data, size) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static long _tcall_thread_self(void)
{
    extern uint64_t oe_thread_self(void);
    return (long)oe_thread_self();
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
            *new_ptr = NULL;
            goto done;
        }

        if (!(*new_ptr = realloc(ptr, size)))
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

        if (!(*new_ptr = memalign(alignment, size)))
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
            if (!(*new_ptr = calloc(size, 1)))
                ERAISE(-ENOMEM);
        }
        else
        {
            if (!(*new_ptr = malloc(size)))
                ERAISE(-ENOMEM);
        }
    }

done:
    return ret;
}

static long _tcall_deallocate(void* ptr)
{
    if (ptr)
        free(ptr);

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

/* Must be overriden by enclave application */
__attribute__((__weak__))
long libos_tcall_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    (void)clk_id;
    (void)tp;

    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
__attribute__((__weak__))
long libos_tcall_isatty(int fd)
{
    (void)fd;

    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
__attribute__((__weak__))
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
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
__attribute__((__weak__))
long libos_tcall_load_symbols(void)
{
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
__attribute__((__weak__))
long libos_tcall_unload_symbols(void)
{
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
__attribute__((__weak__))
long libos_tcall_create_host_thread(uint64_t cookie)
{
    (void)cookie;
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
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

    switch (n)
    {
        case LIBOS_TCALL_RANDOM:
        {
            return _tcall_random((void*)x1, (size_t)x2);
        }
        case LIBOS_TCALL_THREAD_SELF:
        {
            return _tcall_thread_self();
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
                stream  = stdout;
            else if (fd == STDERR_FILENO)
                stream  = stderr;
            else
                return -EINVAL;

            if (fwrite(buf, 1, count, stream) != count)
                return -EIO;

            return (long)count;
        }
        case LIBOS_TCALL_GEN_CREDS:
        {
            uint8_t** cert = (uint8_t**)x1;
            size_t* cert_size = (size_t*)x2;
            uint8_t** pkey = (uint8_t**)x3;
            size_t* pkey_size = (size_t*)x4;

            return libos_gen_creds(cert, cert_size, pkey, pkey_size);
        }
        case LIBOS_TCALL_FREE_CREDS:
        {
            uint8_t* cert = (uint8_t*)x1;
            size_t cert_size = (size_t)x2;
            uint8_t* pkey = (uint8_t*)x3;
            size_t pkey_size = (size_t)x4;

            libos_free_creds(cert, cert_size, pkey, pkey_size);
            return 0;
        }
        case LIBOS_TCALL_CLOCK_GETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return libos_tcall_clock_gettime(clk_id, tp);
        }
        case LIBOS_TCALL_ISATTY:
        {
            int fd = (int)x1;
            return libos_tcall_isatty(fd);
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
        case LIBOS_TCALL_CREATE_HOST_THREAD:
        {
            uint64_t cookie = (uint64_t)x1;
            return libos_tcall_create_host_thread(cookie);
        }
        case SYS_read:
        case SYS_write:
        case SYS_close:
        case SYS_poll:
        case SYS_ioctl:
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
            long ret = oe_syscall(n, x1, x2, x3, x4, x5, x6);

            if (ret == -1)
                ret = -errno;

            return ret;
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}

