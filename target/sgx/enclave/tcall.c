// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <libos/eraise.h>
#include <libos/regions.h>
#include <libos/syscallext.h>
#include <libos/tcall.h>
#include <libos/thread.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include "gencreds.h"

long libos_handle_tcall(long n, long params[6]);

long oe_syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6);

libos_run_thread_t __libos_run_thread;

static long _tcall_random(void* data, size_t size)
{
    long ret = 0;

    if (!data)
        ERAISE(-EINVAL);

    if (oe_random(data, size) != OE_OK)
        ERAISE(-EINVAL);

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
LIBOS_WEAK
long libos_tcall_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    (void)clk_id;
    (void)tp;

    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_clock_settime(clockid_t clk_id, struct timespec* tp)
{
    (void)clk_id;
    (void)tp;

    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
oe_result_t libos_oe_call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    (void)function_id;
    (void)input_buffer;
    (void)input_buffer_size;
    (void)output_buffer;
    (void)output_buffer_size;
    (void)output_bytes_written;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_isatty(int fd)
{
    (void)fd;

    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
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
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_load_symbols(void)
{
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_unload_symbols(void)
{
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_create_thread(uint64_t cookie)
{
    (void)cookie;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    (void)event;
    (void)timeout;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_wake(uint64_t event)
{
    (void)event;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    (void)waiter_event;
    (void)self_event;
    (void)timeout;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

LIBOS_WEAK
long libos_tcall_export_file(const char* path, const void* data, size_t size)
{
    (void)path;
    (void)data;
    (void)size;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

LIBOS_STATIC_ASSERT((sizeof(struct stat) % 8) == 0);
LIBOS_STATIC_ASSERT(sizeof(struct stat) >= 120);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_dev) == 0);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_ino) == 8);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_nlink) == 16);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_mode) == 24);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_uid) == 28);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_gid) == 32);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_rdev) == 40);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_size) == 48);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_blksize) == 56);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_blocks) == 64);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_atim.tv_sec) == 72);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_atim.tv_nsec) == 80);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_mtim.tv_sec) == 88);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_mtim.tv_nsec) == 96);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_ctim.tv_sec) == 104);
LIBOS_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_ctim.tv_nsec) == 112);

LIBOS_WEAK
long libos_tcall_poll_wake(void)
{
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

static long _tcall_target_stat(libos_target_stat_t* buf)
{
    long ret = 0;
    extern oe_sgx_enclave_properties_t oe_enclave_properties_sgx;
    const oe_sgx_enclave_properties_t* p = &oe_enclave_properties_sgx;

    if (!buf)
        ERAISE(-EINVAL);

    memset(buf, 0, sizeof(libos_target_stat_t));

    /* get the kernel memory size (the OE heap size) */
    buf->heap_size = p->header.size_settings.num_heap_pages * OE_PAGE_SIZE;

done:
    return ret;
}

void* _get_gsbase(void)
{
    void* p;
    __asm__ volatile("mov %%gs:0, %0" : "=r"(p));
    return p;
}

static long _tcall_set_tsd(uint64_t value)
{
    libos_td_t* td = _get_gsbase();

    assert(td != NULL);
    td->tsd = value;

    return 0;
}

static long _tcall_get_tsd(uint64_t* value)
{
    libos_td_t* td = _get_gsbase();

    if (!value)
        return -EINVAL;

    assert(td != NULL);
    *value = td->tsd;

    return 0;
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

    (void)x6;

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
        case LIBOS_TCALL_READ_CONSOLE:
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
        case LIBOS_TCALL_VERIFY_CERT:
        {
            uint8_t* cert = (uint8_t*)x1;
            size_t cert_size = (size_t)x2;
            oe_identity_verify_callback_t verifier =
                (oe_identity_verify_callback_t)x3;
            void* arg = (void*)x4;

            return libos_verify_cert(cert, cert_size, verifier, arg);
        }
        case LIBOS_TCALL_CLOCK_GETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return libos_tcall_clock_gettime(clk_id, tp);
        }
        case LIBOS_TCALL_CLOCK_SETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return libos_tcall_clock_settime(clk_id, tp);
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
            return _tcall_target_stat(buf);
        }
        case LIBOS_TCALL_SET_TSD:
        {
            uint64_t value = (uint64_t)x1;
            return _tcall_set_tsd(value);
        }
        case LIBOS_TCALL_GET_TSD:
        {
            uint64_t* value = (uint64_t*)x1;
            return _tcall_get_tsd(value);
        }
        case LIBOS_TCALL_GET_ERRNO_LOCATION:
        {
            int** ptr = (int**)x1;
            libos_td_t* td = _get_gsbase();

            if (!ptr)
                return -EINVAL;

            assert(td != NULL);

            *ptr = &td->errnum;

            return 0;
        }
        case LIBOS_TCALL_POLL_WAKE:
        {
            return libos_tcall_poll_wake();
        }
        case SYS_read:
        case SYS_write:
        case SYS_close:
        case SYS_nanosleep:
        case SYS_fcntl:
        case SYS_bind:
        case SYS_connect:
        case SYS_recvfrom:
        case SYS_sendto:
        case SYS_socket:
        case SYS_accept:
        case SYS_sendmsg:
        case SYS_recvmsg:
        case SYS_shutdown:
        case SYS_listen:
        case SYS_getsockname:
        case SYS_getpeername:
        case SYS_socketpair:
        case SYS_setsockopt:
        case SYS_getsockopt:
        case SYS_ioctl:
        case SYS_fstat:
        case SYS_sched_yield:
        case SYS_fchmod:
        case SYS_poll:
        {
            extern long libos_handle_tcall(long n, long params[6]);
            return libos_handle_tcall(n, params);
        }
        /* Open Enclave extensions */
        case SYS_libos_oe_get_report_v2:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_report_v2(
                (uint32_t)args[0],
                (const uint8_t*)args[1],
                (size_t)args[2],
                (const void*)args[3],
                (size_t)args[4],
                (uint8_t**)args[5],
                (size_t*)args[6]);
        }
        case SYS_libos_oe_free_report:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_report((uint8_t*)args[0]);
            return 0;
        }
        case SYS_libos_oe_get_target_info_v2:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_target_info_v2(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (void**)args[2],
                (size_t*)args[3]);
            return 0;
        }
        case SYS_libos_oe_free_target_info:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_target_info((void*)args[0]);
            return 0;
        }
        case SYS_libos_oe_parse_report:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_parse_report(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (oe_report_t*)args[2]);
        }
        case SYS_libos_oe_verify_report:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_verify_report(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (oe_report_t*)args[2]);
        }
        case SYS_libos_oe_get_seal_key_by_policy_v2:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_seal_key_by_policy_v2(
                (oe_seal_policy_t)args[0],
                (uint8_t**)args[1],
                (size_t*)args[2],
                (uint8_t**)args[3],
                (size_t*)args[4]);
        }
        case SYS_libos_oe_get_public_key_by_policy:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_public_key_by_policy(
                (oe_seal_policy_t)args[0],
                (const oe_asymmetric_key_params_t*)args[1],
                (uint8_t**)args[2],
                (size_t*)args[3],
                (uint8_t**)args[4],
                (size_t*)args[5]);
        }
        case SYS_libos_oe_get_public_key:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_public_key(
                (const oe_asymmetric_key_params_t*)args[0],
                (const uint8_t*)args[1],
                (size_t)args[2],
                (uint8_t**)args[3],
                (size_t*)args[4]);
        }
        case SYS_libos_oe_get_private_key_by_policy:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_private_key_by_policy(
                (oe_seal_policy_t)args[0],
                (const oe_asymmetric_key_params_t*)args[1],
                (uint8_t**)args[2],
                (size_t*)args[3],
                (uint8_t**)args[4],
                (size_t*)args[5]);
        }
        case SYS_libos_oe_get_private_key:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_private_key(
                (const oe_asymmetric_key_params_t*)args[0],
                (const uint8_t*)args[1],
                (size_t)args[2],
                (uint8_t**)args[3],
                (size_t*)args[4]);
        }
        case SYS_libos_oe_free_key:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_key(
                (uint8_t*)args[0],
                (size_t)args[1],
                (uint8_t*)args[2],
                (size_t)args[3]);
            return 0;
        }
        case SYS_libos_oe_get_seal_key_v2:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_seal_key_v2(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (uint8_t**)args[2],
                (size_t*)args[3]);
        }
        case SYS_libos_oe_free_seal_key:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_seal_key((uint8_t*)args[0], (uint8_t*)args[1]);
            return 0;
        }
        case SYS_libos_oe_generate_attestation_certificate:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_generate_attestation_certificate(
                (const unsigned char*)args[0],
                (uint8_t*)args[1],
                (size_t)args[2],
                (uint8_t*)args[3],
                (size_t)args[4],
                (uint8_t**)args[5],
                (size_t*)args[6]);
        }
        case SYS_libos_oe_free_attestation_certificate:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_attestation_certificate((uint8_t*)args[0]);
            return 0;
        }
        case SYS_libos_oe_verify_attestation_certificate:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_verify_attestation_certificate(
                (uint8_t*)args[0],
                (size_t)args[1],
                (oe_identity_verify_callback_t)args[2],
                (void*)args[3]);
        }
        case SYS_libos_oe_result_str:
        {
            uint64_t* args = (uint64_t*)x1;
            return (long)oe_result_str((oe_result_t)args[0]);
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}
