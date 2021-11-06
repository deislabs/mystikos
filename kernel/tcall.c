// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <syscall.h>
#include <unistd.h>

#include <myst/blockdevice.h>
#include <myst/fsgs.h>
#include <myst/luks.h>
#include <myst/sha256.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/thread.h>

long myst_tcall_random(void* data, size_t size)
{
    long params[6] = {(long)data, (long)size};
    return myst_tcall(MYST_TCALL_RANDOM, params);
}

long myst_tcall_vsnprintf(
    char* str,
    size_t size,
    const char* format,
    va_list ap)
{
    long params[6] = {0};
    params[0] = (long)str;
    params[1] = (long)size;
    params[2] = (long)format;
    params[3] = (long)ap;
    return myst_tcall(MYST_TCALL_VSNPRINTF, params);
}

long myst_tcall_read_console(int fd, void* buf, size_t count)
{
    long params[6] = {0};
    params[0] = (long)fd;
    params[1] = (long)buf;
    params[2] = (long)count;
    return myst_tcall(MYST_TCALL_READ_CONSOLE, params);
}

long myst_tcall_write_console(int fd, const void* buf, size_t count)
{
    long params[6] = {0};
    params[0] = (long)fd;
    params[1] = (long)buf;
    params[2] = (long)count;
    return myst_tcall(MYST_TCALL_WRITE_CONSOLE, params);
}

long myst_tcall_create_thread(uint64_t cookie)
{
    long params[6] = {0};
    params[0] = (long)cookie;
    return myst_tcall(MYST_TCALL_CREATE_THREAD, params);
}

long myst_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    long params[6] = {0};
    params[0] = (long)event;
    params[1] = (long)timeout;
    long ret = myst_tcall(MYST_TCALL_WAIT, params);
    return ret;
}

long myst_tcall_wake(uint64_t event)
{
    long params[6] = {0};
    params[0] = (long)event;
    return myst_tcall(MYST_TCALL_WAKE, params);
}

long myst_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    long params[6] = {0};
    params[0] = (long)waiter_event;
    params[1] = (long)self_event;
    params[2] = (long)timeout;
    return myst_tcall(MYST_TCALL_WAKE_WAIT, params);
}

long myst_tcall_set_run_thread_function(myst_run_thread_t function)
{
    long params[6] = {(long)function};
    return myst_tcall(MYST_TCALL_SET_RUN_THREAD_FUNCTION, params);
}

long myst_tcall_target_stat(myst_target_stat_t* target_stat)
{
    long params[6] = {(long)target_stat};
    return myst_tcall(MYST_TCALL_TARGET_STAT, params);
}

long myst_tcall_set_tsd(uint64_t value)
{
    long params[6] = {(long)value};
    return myst_tcall(MYST_TCALL_SET_TSD, params);
}

long myst_tcall_get_tsd(uint64_t* value)
{
    long params[6] = {(long)value};
    return myst_tcall(MYST_TCALL_GET_TSD, params);
}

long myst_tcall_get_errno_location(int** ptr)
{
    long params[6] = {(long)ptr};
    return myst_tcall(MYST_TCALL_GET_ERRNO_LOCATION, params);
}

long myst_tcall_poll_wake(void)
{
    long params[6] = {0};
    return myst_tcall(MYST_TCALL_POLL_WAKE, params);
}

long myst_tcall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long params[6] = {(long)fds, nfds, timeout};
    return myst_tcall(SYS_poll, params);
}

int myst_open_block_device(const char* path, bool read_only)
{
    long params[6] = {(long)path, read_only};
    return myst_tcall(MYST_TCALL_OPEN_BLOCK_DEVICE, params);
}

int myst_close_block_device(int blkdev)
{
    long params[6] = {blkdev};
    return myst_tcall(MYST_TCALL_CLOSE_BLOCK_DEVICE, params);
}

ssize_t myst_read_block_device(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks)
{
    long params[6] = {blkdev, blkno, (long)blocks, num_blocks};
    return myst_tcall(MYST_TCALL_READ_BLOCK_DEVICE, params);
}

int myst_write_block_device(
    int blkdev,
    uint64_t blkno,
    const struct myst_block* blocks,
    size_t num_blocks)
{
    long params[6] = {blkdev, blkno, (long)blocks, num_blocks};
    return myst_tcall(MYST_TCALL_WRITE_BLOCK_DEVICE, params);
}

int myst_luks_encrypt(
    const luks_phdr_t* phdr,
    const void* key,
    const uint8_t* in,
    uint8_t* out,
    size_t size,
    uint64_t secno)
{
    long params[6] = {(long)phdr, (long)key, (long)in, (long)out, size, secno};
    return myst_tcall(MYST_TCALL_LUKS_ENCRYPT, params);
}

int myst_luks_decrypt(
    const luks_phdr_t* phdr,
    const void* key,
    const uint8_t* in,
    uint8_t* out,
    size_t size,
    uint64_t secno)
{
    long params[6] = {(long)phdr, (long)key, (long)in, (long)out, size, secno};
    return myst_tcall(MYST_TCALL_LUKS_DECRYPT, params);
}

int myst_sha256_start(myst_sha256_ctx_t* ctx)
{
    long params[6] = {(long)ctx};
    return myst_tcall(MYST_TCALL_SHA256_START, params);
}

int myst_sha256_update(myst_sha256_ctx_t* ctx, const void* data, size_t size)
{
    long params[6] = {(long)ctx, (long)data, size};
    return myst_tcall(MYST_TCALL_SHA256_UPDATE, params);
}

int myst_sha256_finish(myst_sha256_ctx_t* ctx, myst_sha256_t* sha256)
{
    long params[6] = {(long)ctx, (long)sha256};
    return myst_tcall(MYST_TCALL_SHA256_FINISH, params);
}

int myst_tcall_verify_signature(
    const char* pem_public_key,
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* signer,
    size_t signer_size,
    const uint8_t* signature,
    size_t signature_size)
{
    long args[7] = {(long)pem_public_key,
                    (long)hash,
                    hash_size,
                    (long)signer,
                    signer_size,
                    (long)signature,
                    signature_size};
    long params[6] = {(long)args};
    return myst_tcall(MYST_TCALL_VERIFY_SIGNATURE, params);
}

int myst_tcall_load_fssig(const char* path, myst_fssig_t* fssig)
{
    long params[6] = {(long)path, (long)fssig};
    return myst_tcall(MYST_TCALL_LOAD_FSSIG, params);
}

int myst_tcall_mprotect(void* addr, size_t len, int prot)
{
    long params[6] = {(long)addr, (long)len, (long)prot};
    return myst_tcall(SYS_mprotect, params);
}

#ifdef MYST_ENABLE_GCOV
long myst_gcov(const char* func, long gcov_params[6])
{
    long params[6] = {(long)func, (long)gcov_params};
    return myst_tcall(MYST_TCALL_GCOV, params);
}
#endif

long myst_tcall_close(int fd)
{
    long params[6] = {fd};
    return myst_tcall(SYS_close, params);
}

long myst_tcall_fcntl(int fd, int cmd, long arg)
{
    long params[6] = {fd, cmd, arg};
    return myst_tcall(SYS_fcntl, params);
}

long myst_tcall_fstat(int fd, struct stat* statbuf)
{
    long params[6] = {fd, (long)statbuf};
    return myst_tcall(SYS_fstat, params);
}

long myst_tcall_dup(int oldfd)
{
    long params[6] = {oldfd};
    return myst_tcall(SYS_dup, params);
}

long myst_tcall_read(int fd, void* buf, size_t count)
{
    long params[6] = {fd, (long)buf, count};
    return myst_tcall(SYS_read, params);
}

long myst_tcall_write(int fd, const void* buf, size_t count)
{
    long params[6] = {fd, (long)buf, count};
    return myst_tcall(SYS_write, params);
}

long myst_tcall_pipe2(int pipefd[2], int flags)
{
    long params[6] = {(long)pipefd, flags};
    return myst_tcall(SYS_pipe2, params);
}

long myst_tcall_interrupt_thread(pid_t tid)
{
    long params[6] = {tid};
    return myst_tcall(MYST_TCALL_INTERRUPT_THREAD, params);
}

int myst_tcall_accept4(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int flags)
{
    long params[6] = {sockfd, (long)addr, (long)addrlen, flags};
    return myst_tcall(SYS_accept4, params);
}

int myst_tcall_connect(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    long params[6] = {sockfd, (long)addr, (long)addrlen};
    return myst_tcall(SYS_connect, params);
}

ssize_t myst_tcall_sendto(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    long params[6] = {(long)sockfd,
                      (long)buf,
                      (long)len,
                      (long)flags,
                      (long)dest_addr,
                      (long)addrlen};
    return myst_tcall(SYS_sendto, params);
}

ssize_t myst_tcall_recvfrom(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    long params[6] = {(long)sockfd,
                      (long)buf,
                      (long)len,
                      (long)flags,
                      (long)src_addr,
                      (long)addrlen};
    return myst_tcall(SYS_recvfrom, params);
}

ssize_t myst_tcall_sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
    long params[6] = {(long)sockfd, (long)msg, (long)flags};
    return myst_tcall(SYS_sendmsg, params);
}

ssize_t myst_tcall_recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    long params[6] = {(long)sockfd, (long)msg, (long)flags};
    return myst_tcall(SYS_recvmsg, params);
}

long myst_tcall_read_block(int fd, void* buf, size_t count)
{
    long params[6] = {fd, (long)buf, count};
    return myst_tcall(MYST_TCALL_READ_BLOCK, params);
}

long myst_tcall_write_block(int fd, const void* buf, size_t count)
{
    long params[6] = {fd, (long)buf, count};
    return myst_tcall(MYST_TCALL_WRITE_BLOCK, params);
}

int myst_tcall_accept4_block(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int flags)
{
    long params[6] = {sockfd, (long)addr, (long)addrlen, flags};
    return myst_tcall(MYST_TCALL_ACCEPT4_BLOCK, params);
}

int myst_tcall_connect_block(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    long params[6] = {sockfd, (long)addr, (long)addrlen};
    return myst_tcall(MYST_TCALL_CONNECT_BLOCK, params);
}

ssize_t myst_tcall_sendto_block(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    long params[6] = {(long)sockfd,
                      (long)buf,
                      (long)len,
                      (long)flags,
                      (long)dest_addr,
                      (long)addrlen};
    return myst_tcall(MYST_TCALL_SENDTO_BLOCK, params);
}

ssize_t myst_tcall_recvfrom_block(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    long params[6] = {(long)sockfd,
                      (long)buf,
                      (long)len,
                      (long)flags,
                      (long)src_addr,
                      (long)addrlen};
    return myst_tcall(MYST_TCALL_RECVFROM_BLOCK, params);
}

ssize_t myst_tcall_sendmsg_block(
    int sockfd,
    const struct msghdr* msg,
    int flags)
{
    long params[6] = {(long)sockfd, (long)msg, (long)flags};
    return myst_tcall(MYST_TCALL_SENDMSG_BLOCK, params);
}

ssize_t myst_tcall_recvmsg_block(int sockfd, struct msghdr* msg, int flags)
{
    long params[6] = {(long)sockfd, (long)msg, (long)flags};
    return myst_tcall(MYST_TCALL_RECVMSG_BLOCK, params);
}
