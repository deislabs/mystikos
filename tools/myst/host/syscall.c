#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "myst_u.h"

#define RETURN(EXPR)                     \
    do                                   \
    {                                    \
        long ret = (long)EXPR;           \
        return (ret < 0) ? -errno : ret; \
    } while (0)

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

long myst_bind_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
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
