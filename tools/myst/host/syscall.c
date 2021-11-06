#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <myst/assume.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <sched.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "myst_u.h"

#define RETURN(EXPR)                     \
    do                                   \
    {                                    \
        long ret = (long)EXPR;           \
        return (ret < 0) ? -errno : ret; \
    } while (0)

#define SAVE_CALL_RESTORE_IDENTITY_RETURN(uid, gid, call)                     \
    int ret;                                                                  \
    int saved_errno;                                                          \
    uid_t existing_uid, existing_euid, existing_savuid;                       \
    gid_t existing_gid, existing_egid, existing_savgid;                       \
                                                                              \
    ret = syscall(                                                            \
        SYS_getresuid, &existing_uid, &existing_euid, &existing_savuid);      \
    if (ret != 0)                                                             \
        return ret;                                                           \
                                                                              \
    ret = syscall(                                                            \
        SYS_getresgid, &existing_gid, &existing_egid, &existing_savgid);      \
    if (ret != 0)                                                             \
        return ret;                                                           \
                                                                              \
    /* bypass the CRT wrapper as we only want to set this threads ID */       \
    ret = syscall(SYS_setresgid, -1, gid, -1);                                \
    if (ret != 0)                                                             \
        return ret;                                                           \
                                                                              \
    ret = syscall(SYS_setresuid, -1, uid, -1);                                \
    if (ret != 0)                                                             \
    {                                                                         \
        myst_assume(                                                          \
            syscall(                                                          \
                SYS_setresgid,                                                \
                existing_gid,                                                 \
                existing_egid,                                                \
                existing_savgid) == 0);                                       \
        return ret;                                                           \
    }                                                                         \
                                                                              \
    ret = call;                                                               \
                                                                              \
    saved_errno = errno;                                                      \
                                                                              \
    myst_assume(                                                              \
        syscall(                                                              \
            SYS_setresgid, existing_gid, existing_egid, existing_savgid) ==   \
        0);                                                                   \
    myst_assume(                                                              \
        syscall(SYS_setresuid, existing_uid, existing_euid, existing_euid) == \
        0);                                                                   \
                                                                              \
    errno = saved_errno;                                                      \
    return (ret < 0) ? -errno : ret

static int _set_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
        return -errno;

    if ((flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) < 0)
        return -errno;

    return 0;
}

long myst_read_ocall(int fd, void* buf, size_t count)
{
    RETURN(syscall(SYS_read, fd, buf, count));
}

long myst_read_block_ocall(int fd, void* buf, size_t count)
{
    return myst_interruptible_syscall(
        SYS_read, fd, POLLIN, true, fd, buf, count);
}

long myst_write_ocall(int fd, const void* buf, size_t count)
{
    RETURN(syscall(SYS_write, fd, buf, count));
}

long myst_write_block_ocall(int fd, const void* buf, size_t count)
{
    return myst_interruptible_syscall(
        SYS_write, fd, POLLOUT, true, fd, buf, count);
}

long myst_close_ocall(int fd)
{
    RETURN(close(fd));
}

long myst_nanosleep_ocall(const struct timespec* req, struct timespec* rem)
{
    return myst_tcall_nanosleep(req, rem);
}

long myst_fcntl_ocall(int fd, int cmd, long arg)
{
    RETURN(fcntl(fd, cmd, arg));
}

long myst_fcntl_setlkw_ocall(int fd, const struct flock* arg)
{
    RETURN(fcntl(fd, F_SETLK, arg));
}

long myst_bind_ocall(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    RETURN(bind(sockfd, addr, addrlen));
}

long myst_connect_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    RETURN(syscall(SYS_connect, sockfd, addr, addrlen));
}

long myst_connect_block_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    return myst_tcall_connect_block(sockfd, addr, addrlen);
}

long myst_recvfrom_ocall(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen,
    socklen_t src_addr_size)
{
    RETURN(syscall(SYS_recvfrom, sockfd, buf, len, flags, src_addr, addrlen));
}

long myst_recvfrom_block_ocall(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen,
    socklen_t src_addr_size)
{
    bool retry = true;

    /* Don't retry EAGAIN|EINPPROGRESS if these flags are present */
    if ((flags & (MSG_ERRQUEUE | MSG_DONTWAIT)))
        retry = false;

    return myst_interruptible_syscall(
        SYS_recvfrom,
        sockfd,
        POLLIN,
        retry,
        sockfd,
        buf,
        len,
        flags,
        src_addr,
        addrlen);
}

long myst_sendto_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    RETURN(syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen));
}

long myst_sendto_block_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    bool retry = true;

    /* Don't retry EAGAIN|EINPPROGRESS if this flag is present */
    if ((flags & MSG_DONTWAIT))
        retry = false;

    return myst_interruptible_syscall(
        SYS_sendto,
        sockfd,
        POLLOUT,
        retry,
        sockfd,
        buf,
        len,
        flags,
        dest_addr,
        addrlen);
}

long myst_socket_ocall(int domain, int type, int protocol)
{
    long ret = 0;
    int sockfd;

    ECHECK_ERRNO(sockfd = socket(domain, type, protocol));
    ECHECK(_set_nonblock(sockfd));

    ret = sockfd;

done:

    if (ret < 0 && sockfd >= 0)
        close(sockfd);

    return ret;
}

long myst_accept4_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    size_t addr_size,
    int flags)
{
    long ret = 0;
    int new_sockfd;

    ECHECK_ERRNO(
        new_sockfd = syscall(SYS_accept4, sockfd, addr, addrlen, flags));
    ECHECK(_set_nonblock(new_sockfd));

    ret = new_sockfd;

done:

    if (ret < 0 && new_sockfd >= 0)
        close(new_sockfd);

    return ret;
}

long myst_accept4_block_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    size_t addr_size,
    int flags)
{
    long ret = 0;
    int new_sockfd;

    ECHECK(
        new_sockfd = myst_interruptible_syscall(
            SYS_accept4, sockfd, POLLIN, true, sockfd, addr, addrlen, flags));
    ECHECK(_set_nonblock(new_sockfd));

    ret = new_sockfd;

done:

    if (ret < 0 && new_sockfd >= 0)
        close(new_sockfd);

    return ret;
}

long myst_sendmsg_ocall(
    int sockfd,
    const void* msg_name,
    socklen_t msg_namelen,
    const void* buf,
    size_t len,
    const void* msg_control,
    socklen_t msg_controllen,
    int msg_flags,
    int flags)
{
    struct msghdr msg;
    struct iovec iov;

    /* initialize the msghdr structure */
    msg.msg_name = (void*)msg_name;
    msg.msg_namelen = msg_namelen;
    iov.iov_base = (void*)buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (void*)msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = msg_flags;

    RETURN(syscall(SYS_sendmsg, sockfd, &msg, flags));
}

long myst_sendmsg_block_ocall(
    int sockfd,
    const void* msg_name,
    socklen_t msg_namelen,
    const void* buf,
    size_t len,
    const void* msg_control,
    socklen_t msg_controllen,
    int msg_flags,
    int flags)
{
    struct msghdr msg;
    struct iovec iov;
    bool retry = true;

    /* Don't retry EAGAIN|EINPPROGRESS if this flag is present */
    if ((flags & MSG_DONTWAIT))
        retry = false;

    /* initialize the msghdr structure */
    msg.msg_name = (void*)msg_name;
    msg.msg_namelen = msg_namelen;
    iov.iov_base = (void*)buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (void*)msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = msg_flags;

    return myst_interruptible_syscall(
        SYS_sendmsg, sockfd, POLLOUT, retry, sockfd, &msg, flags);
}

long myst_recvmsg_ocall(
    int sockfd,
    void* msg_name,
    socklen_t msg_namelen,
    socklen_t* msg_namelen_out,
    void* buf,
    size_t len,
    void* msg_control,
    socklen_t msg_controllen,
    socklen_t* msg_controllen_out,
    int* msg_flags,
    int flags)
{
    long ret = 0;
    long retval;
    struct msghdr msg;
    struct iovec iov;

    if (msg_namelen_out)
        *msg_namelen_out = 0;

    if (msg_controllen_out)
        *msg_controllen_out = 0;

    if (msg_flags)
        *msg_flags = 0;

    /* initialize the msghdr structure */
    msg.msg_name = msg_name;
    msg.msg_namelen = msg_namelen;
    iov.iov_base = buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = 0;

    if ((retval = syscall(SYS_recvmsg, sockfd, &msg, flags)) < 0)
    {
        ret = -errno;
        goto done;
    }

    if (msg_namelen_out)
        *msg_namelen_out = msg.msg_namelen;

    if (msg_controllen_out)
        *msg_controllen_out = msg.msg_controllen;

    if (msg_flags)
        *msg_flags = msg.msg_flags;

    ret = retval;

done:
    return ret;
}

long myst_recvmsg_block_ocall(
    int sockfd,
    void* msg_name,
    socklen_t msg_namelen,
    socklen_t* msg_namelen_out,
    void* buf,
    size_t len,
    void* msg_control,
    socklen_t msg_controllen,
    socklen_t* msg_controllen_out,
    int* msg_flags,
    int flags)
{
    long ret = 0;
    long retval;
    struct msghdr msg;
    struct iovec iov;
    bool retry = true;

    /* Don't retry EAGAIN|EINPPROGRESS if these flags are present */
    if ((flags & (MSG_ERRQUEUE | MSG_DONTWAIT)))
        retry = false;

    if (msg_namelen_out)
        *msg_namelen_out = 0;

    if (msg_controllen_out)
        *msg_controllen_out = 0;

    if (msg_flags)
        *msg_flags = 0;

    /* initialize the msghdr structure */
    msg.msg_name = msg_name;
    msg.msg_namelen = msg_namelen;
    iov.iov_base = buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = 0;

    if ((retval = myst_interruptible_syscall(
             SYS_recvmsg, sockfd, POLLIN, retry, sockfd, &msg, flags)) < 0)
    {
        ret = retval;
        goto done;
    }

    if (msg_namelen_out)
        *msg_namelen_out = msg.msg_namelen;

    if (msg_controllen_out)
        *msg_controllen_out = msg.msg_controllen;

    if (msg_flags)
        *msg_flags = msg.msg_flags;

    ret = retval;

done:
    return ret;
}

long myst_shutdown_ocall(int sockfd, int how)
{
    RETURN(shutdown(sockfd, how));
}

long myst_listen_ocall(int sockfd, int backlog)
{
    RETURN(listen(sockfd, backlog));
}

long myst_getsockname_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    socklen_t addr_size)
{
    RETURN(getsockname(sockfd, addr, addrlen));
}

long myst_getpeername_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    socklen_t addr_size)
{
    RETURN(getpeername(sockfd, addr, addrlen));
}

long myst_socketpair_ocall(int domain, int type, int protocol, int sv[2])
{
    long ret = 0;

    sv[0] = -1;
    sv[1] = -1;

    ECHECK_ERRNO(socketpair(domain, type, protocol, sv));
    ECHECK(_set_nonblock(sv[0]));
    ECHECK(_set_nonblock(sv[1]));

done:

    if (ret < 0 && sv[0] >= 0 && sv[1] >= 0)
    {
        close(sv[0]);
        close(sv[1]);
    }

    return ret;
}

long myst_getsockopt_ocall(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen,
    socklen_t optval_size)
{
    RETURN(getsockopt(sockfd, level, optname, optval, optlen));
}

long myst_setsockopt_ocall(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    RETURN(setsockopt(sockfd, level, optname, optval, optlen));
}

long myst_ioctl_ocall(
    int fd,
    unsigned long request,
    void* argp,
    size_t argp_size)
{
    RETURN(ioctl(fd, request, argp));
}

long myst_open_ocall(
    const char* pathname,
    int flags,
    mode_t mode,
    uid_t uid,
    gid_t gid)
{
#ifdef MYST_ENABLE_GCOV
    if (uid == UINT_MAX && gid == UINT_MAX)
        RETURN(open(pathname, flags, mode));
#endif

    SAVE_CALL_RESTORE_IDENTITY_RETURN(uid, gid, open(pathname, flags, mode));
}

long myst_stat_ocall(
    const char* pathname,
    struct myst_stat* statbuf,
    uid_t uid,
    gid_t gid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        uid, gid, stat(pathname, (struct stat*)statbuf));
}

long myst_lstat_ocall(
    const char* pathname,
    struct myst_stat* statbuf,
    uid_t uid,
    gid_t gid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        uid, gid, lstat(pathname, (struct stat*)statbuf));
}

long myst_access_ocall(const char* pathname, int mode)
{
    RETURN(access(pathname, mode));
}

long myst_dup_ocall(int oldfd)
{
    RETURN(dup(oldfd));
}

long myst_pread64_ocall(int fd, void* buf, size_t count, off_t offset)
{
    RETURN(pread(fd, buf, count, offset));
}

long myst_pwrite64_ocall(int fd, const void* buf, size_t count, off_t offset)
{
    RETURN(pwrite(fd, buf, count, offset));
}

long myst_link_ocall(const char* oldpath, const char* newpath)
{
    RETURN(link(oldpath, newpath));
}

long myst_unlink_ocall(const char* pathname)
{
    RETURN(unlink(pathname));
}

long myst_mkdir_ocall(
    const char* pathname,
    mode_t mode,
    uid_t host_euid,
    gid_t host_egid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        host_euid, host_egid, mkdir(pathname, mode));
}

long myst_rmdir_ocall(const char* pathname, uid_t host_euid, gid_t host_egid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(host_euid, host_egid, rmdir(pathname));
}

long myst_getdents64_ocall(
    unsigned int fd,
    struct myst_linux_dirent64* dirp,
    unsigned int count)
{
    RETURN(syscall(SYS_getdents64, fd, dirp, count));
}

long myst_rename_ocall(const char* oldpath, const char* newpath)
{
    RETURN(rename(oldpath, newpath));
}

long myst_truncate_ocall(const char* path, off_t length)
{
    RETURN(truncate(path, length));
}

long myst_ftruncate_ocall(int fd, off_t length)
{
    RETURN(ftruncate(fd, length));
}

long myst_symlink_ocall(
    const char* target,
    const char* linkpath,
    uid_t uid,
    gid_t gid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(uid, gid, symlink(target, linkpath));
}

long myst_readlink_ocall(const char* pathname, char* buf, size_t bufsiz)
{
    RETURN(readlink(pathname, buf, bufsiz));
}

long myst_statfs_ocall(const char* path, struct myst_statfs* buf)
{
    RETURN(statfs(path, (struct statfs*)buf));
}

long myst_fstatfs_ocall(int fd, struct myst_statfs* buf)
{
    RETURN(fstatfs(fd, (struct statfs*)buf));
}

long myst_lseek_ocall(int fd, off_t offset, int whence)
{
    RETURN(lseek(fd, offset, whence));
}

long myst_utimensat_ocall(
    int dirfd,
    const char* pathname,
    const struct timespec times[2],
    int flags,
    uid_t uid,
    gid_t gid)
{
    /* bypass the glibc wrapper (it raises EINVAL when pathname is null */
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        uid, gid, syscall(SYS_utimensat, dirfd, pathname, times, flags));
}

long myst_sched_setaffinity_ocall(
    pid_t pid,
    size_t cpusetsize,
    const uint8_t* mask)
{
    RETURN(syscall(SYS_sched_setaffinity, pid, cpusetsize, mask));
}

long myst_sched_getaffinity_ocall(pid_t pid, size_t cpusetsize, uint8_t* mask)
{
    RETURN(syscall(SYS_sched_getaffinity, pid, cpusetsize, mask));
}

long myst_getcpu_ocall(unsigned* cpu, unsigned* node)
{
    /* note tcache unused since Linux 2.6.24 so we pass null */
    RETURN(syscall(SYS_getcpu, cpu, node, NULL));
}

long myst_chown_ocall(
    const char* pathname,
    uid_t owner,
    gid_t group,
    uid_t host_euid,
    gid_t host_egid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        host_euid, host_egid, chown(pathname, owner, group));
}

long myst_fchown_ocall(
    int fd,
    uid_t owner,
    gid_t group,
    uid_t host_euid,
    gid_t host_egid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        host_euid, host_egid, fchown(fd, owner, group));
}

long myst_lchown_ocall(
    const char* pathname,
    uid_t owner,
    gid_t group,
    uid_t host_euid,
    gid_t host_egid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        host_euid, host_egid, lchown(pathname, owner, group));
}

long myst_chmod_ocall(
    const char* pathname,
    mode_t mode,
    uid_t host_euid,
    gid_t host_egid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(
        host_euid, host_egid, chmod(pathname, mode));
}

long myst_fchmod_ocall(int fd, uint32_t mode, uid_t host_euid, gid_t host_egid)
{
    SAVE_CALL_RESTORE_IDENTITY_RETURN(host_euid, host_egid, fchmod(fd, mode));
}

long myst_fdatasync_ocall(int fd)
{
    RETURN(fdatasync(fd));
}

long myst_fsync_ocall(int fd)
{
    RETURN(fsync(fd));
}

long myst_pipe2_ocall(int pipefd[2], int flags)
{
    long ret = 0;

    pipefd[0] = -1;
    pipefd[1] = -1;

    ECHECK_ERRNO(pipe2(pipefd, flags));
    ECHECK(_set_nonblock(pipefd[0]));
    ECHECK(_set_nonblock(pipefd[1]));

done:

    if (ret < 0 && pipefd[0] >= 0 && pipefd[1] >= 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
    }

    return ret;
}

long myst_epoll_create1_ocall(int flags)
{
    RETURN(epoll_create1(flags));
}

long myst_epoll_wait_ocall(
    int epfd,
    struct epoll_event* events,
    size_t maxevents,
    int timeout)
{
    return myst_tcall_epoll_wait(epfd, events, maxevents, timeout);
}

long myst_epoll_ctl_ocall(
    int epfd,
    int op,
    int fd,
    const struct epoll_event* event)
{
    RETURN(epoll_ctl(epfd, op, fd, (struct epoll_event*)event));
}

long myst_eventfd_ocall(unsigned int initval, int flags)
{
    RETURN(eventfd(initval, flags));
}
