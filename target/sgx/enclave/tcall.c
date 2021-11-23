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

#include <myst/eraise.h>
#include <myst/fssig.h>
#include <myst/luks.h>
#include <myst/regions.h>
#include <myst/sha256.h>
#include <myst/tcall.h>
#include <myst/tee.h>
#include <myst/thread.h>
#include <oeprivate/rsa.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include "gencreds.h"

long myst_handle_tcall(long n, long params[6]);

long oe_syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6);

myst_run_thread_t __myst_run_thread;

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
MYST_WEAK
long myst_tcall_clock_getres(clockid_t clk_id, struct timespec* res)
{
    (void)clk_id;
    (void)res;

    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    (void)clk_id;
    (void)tp;

    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_clock_settime(clockid_t clk_id, struct timespec* tp)
{
    (void)clk_id;
    (void)tp;

    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
oe_result_t myst_oe_call_host_function(
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
MYST_WEAK
long myst_tcall_isatty(int fd)
{
    (void)fd;

    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text,
    size_t text_size,
    const char* enclave_rootfs_path)
{
    (void)file_data;
    (void)file_size;
    (void)text;
    (void)text_size;
    (void)enclave_rootfs_path;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_load_symbols(void)
{
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_unload_symbols(void)
{
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_create_thread(uint64_t cookie)
{
    (void)cookie;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    (void)event;
    (void)timeout;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_wake(uint64_t event)
{
    (void)event;
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

/* Must be overriden by enclave application */
MYST_WEAK
long myst_tcall_wake_wait(
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

MYST_STATIC_ASSERT((sizeof(struct stat) % 8) == 0);
MYST_STATIC_ASSERT(sizeof(struct stat) >= 120);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_dev) == 0);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_ino) == 8);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_nlink) == 16);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_mode) == 24);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_uid) == 28);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_gid) == 32);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_rdev) == 40);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_size) == 48);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_blksize) == 56);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_blocks) == 64);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_atim.tv_sec) == 72);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_atim.tv_nsec) == 80);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_mtim.tv_sec) == 88);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_mtim.tv_nsec) == 96);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_ctim.tv_sec) == 104);
MYST_STATIC_ASSERT(OE_OFFSETOF(struct stat, st_ctim.tv_nsec) == 112);

MYST_WEAK
long myst_tcall_poll_wake(void)
{
    assert("sgx: unimplemented: implement in enclave" == NULL);
    return -ENOTSUP;
}

static long _tcall_target_stat(myst_target_stat_t* buf)
{
    long ret = 0;
    extern oe_sgx_enclave_properties_t oe_enclave_properties_sgx;
    const oe_sgx_enclave_properties_t* p = &oe_enclave_properties_sgx;

    if (!buf)
        ERAISE(-EINVAL);

    memset(buf, 0, sizeof(myst_target_stat_t));

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
    myst_td_t* td = _get_gsbase();

    assert(td != NULL);
    td->tsd = value;

    return 0;
}

static long _tcall_get_tsd(uint64_t* value)
{
    myst_td_t* td = _get_gsbase();

    if (!value)
        return -EINVAL;

    assert(td != NULL);
    *value = td->tsd;

    return 0;
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

    (void)x6;

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

            return myst_tcall_write_console(fd, buf, count);
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
        case MYST_TCALL_GEN_CREDS:
        {
            uint8_t** cert = (uint8_t**)x1;
            size_t* cert_size = (size_t*)x2;
            uint8_t** pkey = (uint8_t**)x3;
            size_t* pkey_size = (size_t*)x4;

            return myst_gen_creds(cert, cert_size, pkey, pkey_size);
        }
        case MYST_TCALL_FREE_CREDS:
        {
            uint8_t* cert = (uint8_t*)x1;
            size_t cert_size = (size_t)x2;
            uint8_t* pkey = (uint8_t*)x3;
            size_t pkey_size = (size_t)x4;
            uint8_t* report = (uint8_t*)x5;
            size_t report_size = (size_t)x6;

            myst_free_creds(
                cert, cert_size, pkey, pkey_size, report, report_size);
            return 0;
        }
        case MYST_TCALL_GEN_CREDS_EX:
        {
            uint8_t** cert = (uint8_t**)x1;
            size_t* cert_size = (size_t*)x2;
            uint8_t** pkey = (uint8_t**)x3;
            size_t* pkey_size = (size_t*)x4;
            uint8_t** report = (uint8_t**)x5;
            size_t* report_size = (size_t*)x6;

            return myst_gen_creds_ex(
                cert, cert_size, pkey, pkey_size, report, report_size);
        }
        case MYST_TCALL_VERIFY_CERT:
        {
            uint8_t* cert = (uint8_t*)x1;
            size_t cert_size = (size_t)x2;
            oe_identity_verify_callback_t verifier =
                (oe_identity_verify_callback_t)x3;
            void* arg = (void*)x4;

            return myst_verify_cert(cert, cert_size, verifier, arg);
        }
        case MYST_TCALL_CLOCK_GETRES:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* res = (struct timespec*)x2;
            return myst_tcall_clock_getres(clk_id, res);
        }
        case MYST_TCALL_CLOCK_GETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return myst_tcall_clock_gettime(clk_id, tp);
        }
        case MYST_TCALL_CLOCK_SETTIME:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            return myst_tcall_clock_settime(clk_id, tp);
        }
        case MYST_TCALL_ISATTY:
        {
            int fd = (int)x1;
            return myst_tcall_isatty(fd);
        }
        case MYST_TCALL_ADD_SYMBOL_FILE:
        {
            const void* file_data = (const void*)x1;
            size_t file_size = (size_t)x2;
            const void* text = (const void*)x3;
            size_t text_size = (size_t)x4;
            const char* enclave_rootfs_path = (const char*)x5;
            return myst_tcall_add_symbol_file(
                file_data, file_size, text, text_size, enclave_rootfs_path);
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
            int** ptr = (int**)x1;
            myst_td_t* td = _get_gsbase();

            if (!ptr)
                return -EINVAL;

            assert(td != NULL);

            *ptr = &td->errnum;

            return 0;
        }
        case MYST_TCALL_POLL_WAKE:
        {
            return myst_tcall_poll_wake();
        }
        case MYST_TCALL_OPEN_BLOCK_DEVICE:
        {
            return myst_tcall_open_block_device((const char*)x1, (bool)x2);
        }
        case MYST_TCALL_CLOSE_BLOCK_DEVICE:
        {
            return myst_tcall_close_block_device((int)x1);
        }
        case MYST_TCALL_READ_BLOCK_DEVICE:
        {
            return myst_tcall_read_block_device(
                (int)x1, (uint64_t)x2, (struct myst_block*)x3, (size_t)x4);
        }
        case MYST_TCALL_WRITE_BLOCK_DEVICE:
        {
            return myst_tcall_write_block_device(
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
#ifdef MYST_ENABLE_GCOV
        case MYST_TCALL_GCOV:
        {
            extern long myst_gcov(const char* func, long gcov_params[6]);
            const char* func = (const char*)x1;
            long* gcov_params = (long*)x2;
            return myst_gcov(func, gcov_params);
        }
#endif
        case MYST_TCALL_INTERRUPT_THREAD:
        {
            return myst_tcall_interrupt_thread((pid_t)x1);
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
        case SYS_accept4:
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
        case SYS_sched_getparam:
        case SYS_fchmod:
        case SYS_poll:
        case SYS_open:
        case SYS_stat:
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
        case SYS_utimensat:
        case SYS_mprotect:
        case SYS_sched_setaffinity:
        case SYS_sched_getaffinity:
        case SYS_getcpu:
        case SYS_chown:
        case SYS_fchown:
        case SYS_lchown:
        case SYS_chmod:
        case SYS_fdatasync:
        case SYS_fsync:
        case SYS_pipe2:
        case SYS_epoll_create1:
        case SYS_epoll_wait:
        case SYS_epoll_ctl:
        case SYS_eventfd2:
        case MYST_TCALL_ACCEPT4_BLOCK:
        case MYST_TCALL_CONNECT_BLOCK:
        case MYST_TCALL_READ_BLOCK:
        case MYST_TCALL_WRITE_BLOCK:
        case MYST_TCALL_SENDTO_BLOCK:
        case MYST_TCALL_RECVFROM_BLOCK:
        case MYST_TCALL_SENDMSG_BLOCK:
        case MYST_TCALL_RECVMSG_BLOCK:
        {
            extern long myst_handle_tcall(long n, long params[6]);
            return myst_handle_tcall(n, params);
        }
        /* Open Enclave extensions */
        case SYS_myst_oe_get_report_v2:
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
        case SYS_myst_oe_free_report:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_report((uint8_t*)args[0]);
            return 0;
        }
        case SYS_myst_oe_get_target_info_v2:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_target_info_v2(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (void**)args[2],
                (size_t*)args[3]);
            return 0;
        }
        case SYS_myst_oe_free_target_info:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_target_info((void*)args[0]);
            return 0;
        }
        case SYS_myst_oe_parse_report:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_parse_report(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (oe_report_t*)args[2]);
        }
        case SYS_myst_oe_verify_report:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_verify_report(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (oe_report_t*)args[2]);
        }
        case SYS_myst_oe_get_seal_key_by_policy_v2:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_seal_key_by_policy_v2(
                (oe_seal_policy_t)args[0],
                (uint8_t**)args[1],
                (size_t*)args[2],
                (uint8_t**)args[3],
                (size_t*)args[4]);
        }
        case SYS_myst_oe_get_public_key_by_policy:
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
        case SYS_myst_oe_get_public_key:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_public_key(
                (const oe_asymmetric_key_params_t*)args[0],
                (const uint8_t*)args[1],
                (size_t)args[2],
                (uint8_t**)args[3],
                (size_t*)args[4]);
        }
        case SYS_myst_oe_get_private_key_by_policy:
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
        case SYS_myst_oe_get_private_key:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_private_key(
                (const oe_asymmetric_key_params_t*)args[0],
                (const uint8_t*)args[1],
                (size_t)args[2],
                (uint8_t**)args[3],
                (size_t*)args[4]);
        }
        case SYS_myst_oe_free_key:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_key(
                (uint8_t*)args[0],
                (size_t)args[1],
                (uint8_t*)args[2],
                (size_t)args[3]);
            return 0;
        }
        case SYS_myst_oe_get_seal_key_v2:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_get_seal_key_v2(
                (const uint8_t*)args[0],
                (size_t)args[1],
                (uint8_t**)args[2],
                (size_t*)args[3]);
        }
        case SYS_myst_oe_free_seal_key:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_seal_key((uint8_t*)args[0], (uint8_t*)args[1]);
            return 0;
        }
        case SYS_myst_oe_generate_attestation_certificate:
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
        case SYS_myst_oe_free_attestation_certificate:
        {
            uint64_t* args = (uint64_t*)x1;
            oe_free_attestation_certificate((uint8_t*)args[0]);
            return 0;
        }
        case SYS_myst_oe_verify_attestation_certificate:
        {
            uint64_t* args = (uint64_t*)x1;
            return oe_verify_attestation_certificate(
                (uint8_t*)args[0],
                (size_t)args[1],
                (oe_identity_verify_callback_t)args[2],
                (void*)args[3]);
        }
        case SYS_myst_oe_result_str:
        {
            uint64_t* args = (uint64_t*)x1;
            return (long)oe_result_str((oe_result_t)args[0]);
        }
        case SYS_myst_oe_get_enclave_start_address:
        {
            extern const void* __oe_get_enclave_start_address(void);
            return (long)__oe_get_enclave_start_address();
        }
        case SYS_myst_oe_get_enclave_base_address:
        {
            extern const void* __oe_get_enclave_base_address(void);
            return (long)__oe_get_enclave_base_address();
        }
        default:
        {
            printf("error: tcall=%ld\n", n);
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}
