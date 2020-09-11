#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libos/eraise.h>
#include <libos/syscallext.h>
#include <libos/tcall.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "gencreds.h"

long oe_syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6);

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
LIBOS_WEAK
long libos_tcall_clock_gettime(
    clockid_t clk_id,
    struct timespec* tp)
{
    (void)clk_id;
    (void)tp;

    assert("unimplemented: implement in enclave" == NULL);
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
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_isatty(int fd)
{
    (void)fd;

    assert("unimplemented: implement in enclave" == NULL);
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
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_load_symbols(void)
{
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_unload_symbols(void)
{
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_create_host_thread(uint64_t cookie)
{
    (void)cookie;
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_wait(
    uint64_t event,
    const struct timespec* timeout)
{
    (void)event;
    (void)timeout;
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
LIBOS_WEAK
long libos_tcall_wake(uint64_t event)
{
    (void)event;
    assert("unimplemented: implement in enclave" == NULL);
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
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

LIBOS_WEAK
long libos_tcall_export_file(
    const char* path,
    const void* data,
    size_t size)
{
    (void)path;
    (void)data;
    (void)size;
    assert("unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* forward system call to Open Enclave */
static long
_forward_syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    long ret;

    if ((ret = oe_syscall(n, x1, x2, x3, x4, x5, x6)) == -1)
        ret = -errno;

    return ret;
}

static long _oesdk_syscall(long n, long params[6])
{
    switch (n)
    {
        case SYS_libos_oe_is_within_enclave:
        {
            const void* ptr = (void*)params[0];
            size_t size = (size_t)params[1];
            return (long)oe_is_within_enclave(ptr, size);
        }
        case SYS_libos_oe_is_outside_enclave:
        {
            const void* ptr = (void*)params[0];
            size_t size = (size_t)params[1];
            return (long)oe_is_outside_enclave(ptr, size);
        }
        case SYS_libos_oe_random:
        {
            void* data = (void*)params[0];
            size_t size = (size_t)params[1];
            return (long)oe_random(data, size);
        }
        case SYS_libos_oe_generate_attestation_certificate:
        {
            const unsigned char* subject_name = (const unsigned char*)params[0];
            uint8_t* private_key = (uint8_t*)params[1];
            size_t private_key_size = (size_t)params[2];
            uint8_t* public_key = (uint8_t*)params[3];
            size_t public_key_size = (size_t)params[4];
            long* extra = (long*)params[5];
            uint8_t** output_cert = (uint8_t**)extra[0];
            size_t* output_cert_size = (size_t*)extra[1];

            return (long)oe_generate_attestation_certificate(
                subject_name,
                private_key,
                private_key_size,
                public_key,
                public_key_size,
                output_cert,
                output_cert_size);
        }
        case SYS_libos_oe_get_public_key_by_policy:
        {
            oe_seal_policy_t seal_policy = (oe_seal_policy_t)params[0];
            const oe_asymmetric_key_params_t* key_params = (void*)params[1];
            uint8_t** key_buffer = (uint8_t**)params[2];
            size_t* key_buffer_size = (size_t*)params[3];
            uint8_t** key_info = (uint8_t**)params[4];
            size_t* key_info_size = (size_t*)params[5];

            return (long)oe_get_public_key_by_policy(
                seal_policy,
                key_params,
                key_buffer,
                key_buffer_size,
                key_info,
                key_info_size);
        }
        case SYS_libos_oe_get_private_key_by_policy:
        {
            oe_seal_policy_t seal_policy = (oe_seal_policy_t)params[0];
            const oe_asymmetric_key_params_t* key_params = (void*)params[1];
            uint8_t** key_buffer = (uint8_t**)params[2];
            size_t* key_buffer_size = (size_t*)params[3];
            uint8_t** key_info = (uint8_t**)params[4];
            size_t* key_info_size = (size_t*)params[5];

            return (long)oe_get_private_key_by_policy(
                seal_policy,
                key_params,
                key_buffer,
                key_buffer_size,
                key_info,
                key_info_size);
        }
        case SYS_libos_oe_free_key:
        {
            uint8_t* key_buffer = (uint8_t*)params[0];
            size_t key_buffer_size = (size_t)params[1];
            uint8_t* key_info = (uint8_t*)params[2];
            size_t key_info_size = (size_t)params[3];

            oe_free_key(key_buffer, key_buffer_size, key_info, key_info_size);

            return 0;
        }
        case SYS_libos_oe_free_attestation_certificate:
        {
            uint8_t* cert = (uint8_t*)params[0];

            oe_free_attestation_certificate(cert);

            return 0;
        }
        case SYS_libos_oe_verify_attestation_certificate:
        {
            uint8_t* cert_in_der = (uint8_t*)params[0];
            size_t cert_in_der_len = (size_t)params[1];
            oe_identity_verify_callback_t enclave_identity_callback =
                (oe_identity_verify_callback_t)params[2];
            void* arg = (void*)params[3];

            return (long)oe_verify_attestation_certificate(
                cert_in_der, cert_in_der_len, enclave_identity_callback, arg);
        }
        case SYS_libos_oe_get_enclave_status:
        {
            return (long)oe_get_enclave_status();
        }
        case SYS_libos_oe_allocate_ocall_buffer:
        {
            size_t size = (size_t)params[0];
            return (long)oe_allocate_ocall_buffer(size);
        }
        case SYS_libos_oe_free_ocall_buffer:
        {
            void* buffer = (void*)params[0];
            oe_free_ocall_buffer(buffer);
            return 0;
        }
        case SYS_libos_oe_call_host_function:
        {
            size_t function_id = (size_t)params[0];
            const void* input_buffer = (const void*)params[1];
            size_t input_buffer_size = (size_t)params[2];
            void* output_buffer = (void*)params[3];
            size_t output_buffer_size = (size_t)params[4];
            size_t* output_bytes_written = (size_t*)params[5];

            return (long)libos_oe_call_host_function(
                function_id,
                input_buffer,
                input_buffer_size,
                output_buffer,
                output_buffer_size,
                output_bytes_written);
        }
        case SYS_libos_oe_add_vectored_exception_handler:
        case SYS_libos_oe_remove_vectored_exception_handler:
        case SYS_libos_oe_host_malloc:
        case SYS_libos_oe_host_realloc:
        case SYS_libos_oe_host_calloc:
        case SYS_libos_oe_host_free:
        case SYS_libos_oe_strndup:
        case SYS_libos_oe_abort:
        case SYS_libos_oe_assert_fail:
        case SYS_libos_oe_get_report_v2:
        case SYS_libos_oe_free_report:
        case SYS_libos_oe_get_target_info_v2:
        case SYS_libos_oe_free_target_info:
        case SYS_libos_oe_parse_report:
        case SYS_libos_oe_verify_report:
        case SYS_libos_oe_get_seal_key_by_policy_v2:
        case SYS_libos_oe_get_public_key:
        case SYS_libos_oe_get_private_key:
        case SYS_libos_oe_get_seal_key_v2:
        case SYS_libos_oe_free_seal_key:
        case SYS_libos_oe_get_enclave:
        case SYS_libos_oe_load_module_host_file_system:
        case SYS_libos_oe_load_module_host_socket_interface:
        case SYS_libos_oe_load_module_host_resolver:
        case SYS_libos_oe_load_module_host_epoll:
        case SYS_libos_oe_sgx_set_minimum_crl_tcb_issue_date:
        case SYS_libos_oe_result_str:
        {
            return (long)OE_UNSUPPORTED;
        }
        default:
        {
            assert("unsupported OE TCALL" == NULL);
            return (long)OE_UNSUPPORTED;
        }
    }
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
                stream = stdout;
            else if (fd == STDERR_FILENO)
                stream = stderr;
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
        case SYS_libos_oe_add_vectored_exception_handler:
        case SYS_libos_oe_remove_vectored_exception_handler:
        case SYS_libos_oe_is_within_enclave:
        case SYS_libos_oe_is_outside_enclave:
        case SYS_libos_oe_host_malloc:
        case SYS_libos_oe_host_realloc:
        case SYS_libos_oe_host_calloc:
        case SYS_libos_oe_host_free:
        case SYS_libos_oe_strndup:
        case SYS_libos_oe_abort:
        case SYS_libos_oe_assert_fail:
        case SYS_libos_oe_get_report_v2:
        case SYS_libos_oe_free_report:
        case SYS_libos_oe_get_target_info_v2:
        case SYS_libos_oe_free_target_info:
        case SYS_libos_oe_parse_report:
        case SYS_libos_oe_verify_report:
        case SYS_libos_oe_get_seal_key_by_policy_v2:
        case SYS_libos_oe_get_public_key_by_policy:
        case SYS_libos_oe_get_public_key:
        case SYS_libos_oe_get_private_key_by_policy:
        case SYS_libos_oe_get_private_key:
        case SYS_libos_oe_free_key:
        case SYS_libos_oe_get_seal_key_v2:
        case SYS_libos_oe_free_seal_key:
        case SYS_libos_oe_get_enclave:
        case SYS_libos_oe_random:
        case SYS_libos_oe_generate_attestation_certificate:
        case SYS_libos_oe_free_attestation_certificate:
        case SYS_libos_oe_verify_attestation_certificate:
        case SYS_libos_oe_load_module_host_file_system:
        case SYS_libos_oe_load_module_host_socket_interface:
        case SYS_libos_oe_load_module_host_resolver:
        case SYS_libos_oe_load_module_host_epoll:
        case SYS_libos_oe_sgx_set_minimum_crl_tcb_issue_date:
        case SYS_libos_oe_result_str:
        case SYS_libos_oe_get_enclave_status:
        case SYS_libos_oe_allocate_ocall_buffer:
        case SYS_libos_oe_free_ocall_buffer:
        case SYS_libos_oe_call_host_function:
        {
            return _oesdk_syscall(n, params);
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}
