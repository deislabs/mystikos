#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <myst/assume.h>
#include <myst/defs.h>
#include <sched.h>
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

long myst_read_ocall(int fd, void* buf, size_t count)
{
    RETURN(read(fd, buf, count));
}

long myst_write_ocall(int fd, const void* buf, size_t count)
{
    RETURN(write(fd, buf, count));
}

long myst_close_ocall(int fd)
{
    RETURN(close(fd));
}

long myst_nanosleep_ocall(const struct timespec* req, struct timespec* rem)
{
    RETURN(nanosleep(req, rem));
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
    RETURN(connect(sockfd, addr, addrlen));
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
    RETURN(recvfrom(sockfd, buf, len, flags, src_addr, addrlen));
}

long myst_sendto_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    RETURN(sendto(sockfd, buf, len, flags, dest_addr, addrlen));
}

long myst_socket_ocall(int domain, int type, int protocol)
{
    RETURN(socket(domain, type, protocol));
}

long myst_accept4_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    size_t addr_size,
    int flags)
{
    RETURN(accept4(sockfd, addr, addrlen, flags));
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

    RETURN(sendmsg(sockfd, &msg, flags));
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

    if ((retval = recvmsg(sockfd, &msg, flags)) < 0)
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
    RETURN(socketpair(domain, type, protocol, sv));
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

long myst_lstat_ocall(const char* pathname, struct myst_stat* statbuf)
{
    RETURN(lstat(pathname, (struct stat*)statbuf));
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

long myst_mkdir_ocall(const char* pathname, mode_t mode)
{
    RETURN(mkdir(pathname, mode));
}

long myst_rmdir_ocall(const char* pathname)
{
    RETURN(rmdir(pathname));
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

long myst_symlink_ocall(const char* target, const char* linkpath)
{
    RETURN(symlink(target, linkpath));
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
    const struct myst_cpu_set* mask)
{
    RETURN(syscall(SYS_sched_setaffinity, pid, cpusetsize, mask));
}

MYST_STATIC_ASSERT(sizeof(struct myst_cpu_set) == sizeof(cpu_set_t));

long myst_sched_getaffinity_ocall(
    pid_t pid,
    size_t cpusetsize,
    struct myst_cpu_set* mask)
{
    RETURN(syscall(SYS_sched_getaffinity, pid, cpusetsize, mask));
}

long myst_getcpu_ocall(
    unsigned* cpu,
    unsigned* node,
    struct myst_getcpu_cache* tcache)
{
    RETURN(syscall(SYS_getcpu, cpu, node, tcache));
}
