#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <libos/eraise.h>
#include <libos/panic.h>
#include <libos/sockdev.h>
#include <libos/spinlock.h>
#include <libos/syscall.h>
#include <libos/tcall.h>

#define MAGIC 0xc436d7e6

struct libos_sock
{
    uint32_t magic; /* MAGIC */
    int fd;         /* the target-relative file descriptor */
};

LIBOS_INLINE bool _valid_sock(const libos_sock_t* sock)
{
    return sock && sock->magic == MAGIC;
}

static void _free_sock(libos_sock_t* sock)
{
    if (sock)
    {
        memset(sock, 0, sizeof(libos_sock_t));
        free(sock);
    }
}

static int _new_sock(libos_sock_t** sock_out)
{
    int ret = 0;
    libos_sock_t* sock = NULL;

    if (!sock_out)
        ERAISE(-EINVAL);

    if (!(sock = calloc(1, sizeof(libos_sock_t))))
        ERAISE(-ENOMEM);

    sock->magic = MAGIC;

    *sock_out = sock;
    sock = NULL;

done:

    if (sock)
        _free_sock(sock);

    return ret;
}

/* ATTN: remove this! */
#pragma GCC diagnostic ignored "-Wunused-parameter"

static int _sd_socket(
    libos_sockdev_t* sd,
    int domain,
    int type,
    int protocol,
    libos_sock_t** sock_out)
{
    int ret = 0;
    libos_sock_t* sock = NULL;
    long fd;

    if (sock_out)
        *sock_out = NULL;

    if (!sd || !sock_out)
        ERAISE(-EINVAL);

    ECHECK(_new_sock(&sock));

    /* perform syscall */
    {
        long params[6] = {domain, type, protocol};
        ECHECK(fd = libos_tcall(SYS_socket, params));
    }

    sock->fd = (int)fd;
    *sock_out = sock;
    sock = NULL;

done:

    if (sock)
        _free_sock(sock);

    return ret;
}

static int _sd_socketpair(
    libos_sockdev_t* sd,
    int domain,
    int type,
    int protocol,
    libos_sock_t* pair[2])
{
    int ret = 0;
    libos_sock_t* sock0 = NULL;
    libos_sock_t* sock1 = NULL;
    int sv[2];

    if (!sd || !pair)
        ERAISE(-EINVAL);

    if (!(sock0 = calloc(1, sizeof(libos_sock_t))))
        ERAISE(-ENOMEM);

    if (!(sock1 = calloc(1, sizeof(libos_sock_t))))
        ERAISE(-ENOMEM);

    /* perform syscall */
    {
        long params[6] = {domain, type, protocol, (long)sv};
        ECHECK(libos_tcall(SYS_socketpair, params));
    }

    sock0->magic = MAGIC;
    sock0->fd = sv[0];
    pair[0] = sock0;
    sock0 = NULL;

    sock1->magic = MAGIC;
    sock1->fd = sv[1];
    pair[1] = sock1;
    sock1 = NULL;

done:

    if (sock0)
        free(sock0);

    if (sock1)
        free(sock1);

    return ret;
}

static int _sd_connect(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, addrlen};
        ECHECK(libos_tcall(SYS_connect, params));
    }

done:
    return ret;
}

static int _sd_accept(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen,
    libos_sock_t** new_sock_out)
{
    int ret = 0;
    libos_sock_t* new_sock = NULL;
    int fd;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ECHECK(_new_sock(&new_sock));

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, (long)addrlen};
        ECHECK((fd = libos_tcall(SYS_accept, params)));
    }

    new_sock->fd = fd;
    *new_sock_out = new_sock;
    new_sock = NULL;

done:

    if (new_sock)
        _free_sock(new_sock);

    return ret;
}

static int _sd_bind(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, addrlen};
        ECHECK(libos_tcall(SYS_bind, params));
    }

done:

    return ret;
}

static int _sd_listen(libos_sockdev_t* sd, libos_sock_t* sock, int backlog)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, backlog};
        ECHECK(libos_tcall(SYS_listen, params));
    }

done:

    return ret;
}

static ssize_t _sd_sendto(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {
            sock->fd, (long)buf, len, flags, (long)dest_addr, (long)addrlen};

        ECHECK((ret = libos_tcall(SYS_sendto, params)));
    }

done:
    return ret;
}

static ssize_t _sd_recvfrom(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {
            sock->fd, (long)buf, len, flags, (long)src_addr, (long)addrlen};

        ECHECK((ret = libos_tcall(SYS_recvfrom, params)));
    }

done:
    return ret;
}

static int _sd_sendmsg(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    const struct msghdr* msg,
    int flags)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)msg, flags};
        ECHECK((ret = libos_tcall(SYS_sendmsg, params)));
    }

done:
    return ret;
}

static int _sd_recvmsg(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    struct msghdr* msg,
    int flags)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)msg, flags};
        ECHECK((ret = libos_tcall(SYS_recvmsg, params)));
    }

done:
    return ret;
}

static int _sd_shutdown(libos_sockdev_t* sd, libos_sock_t* sock, int how)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, how};
        ECHECK(libos_tcall(SYS_shutdown, params));
    }

done:
    return ret;
}

static int _sd_getsockopt(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, level, optname, (long)optval, (long)optlen};
        ECHECK(libos_tcall(SYS_getsockopt, params));
    }

done:
    return ret;
}

static int _sd_setsockopt(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, level, optname, (long)optval, (long)optlen};
        ECHECK(libos_tcall(SYS_setsockopt, params));
    }

done:
    return ret;
}

static int _sd_getpeername(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, (long)addrlen};
        ECHECK(libos_tcall(SYS_getpeername, params));
    }

done:
    return ret;
}

static int _sd_getsockname(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, (long)addrlen};
        ECHECK(libos_tcall(SYS_getsockname, params));
    }

done:
    return ret;
}

static ssize_t _sd_read(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)buf, count};
        ECHECK((ret = libos_tcall(SYS_read, params)));
    }

done:
    return ret;
}

static ssize_t _sd_write(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)buf, count};
        ECHECK((ret = libos_tcall(SYS_write, params)));
    }

done:
    return ret;
}

static ssize_t _sd_readv(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)iov, iovcnt};
        ECHECK((ret = libos_tcall(SYS_readv, params)));
    }

done:
    return ret;
}

static ssize_t _sd_writev(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)iov, iovcnt};
        ECHECK((ret = libos_tcall(SYS_writev, params)));
    }

done:
    return ret;
}

static int _sd_fstat(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    struct stat* statbuf)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)statbuf};
        ECHECK(libos_tcall(SYS_fstat, params));
    }

done:
    return ret;
}

static int _sd_ioctl(
    libos_sockdev_t* sd,
    libos_sock_t* sock,
    unsigned long request,
    long arg)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, request, arg};
        ECHECK(libos_tcall(SYS_ioctl, params));
    }

done:
    return ret;
}

static int _sd_fcntl(libos_sockdev_t* sd, libos_sock_t* sock, int cmd, long arg)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, cmd, arg};
        ECHECK((ret = libos_tcall(SYS_fcntl, params)));
    }

done:
    return ret;
}

static int _sd_dup(
    libos_sockdev_t* sd,
    const libos_sock_t* sock,
    libos_sock_t** sock_out)
{
    int ret = 0;
    libos_sock_t* new_sock = NULL;
    long fd;

    if (sock_out)
        *sock_out = NULL;

    if (!sd || !_valid_sock(sock) || !sock_out)
        ERAISE(-EINVAL);

    if (!(new_sock = calloc(1, sizeof(libos_sock_t))))
        ERAISE(-ENOMEM);

    /* perform syscall */
    {
        long params[6] = {sock->fd};
        ECHECK((fd = libos_tcall(SYS_dup, params)));
    }

    new_sock->magic = MAGIC;
    new_sock->fd = (int)fd;
    *sock_out = new_sock;
    new_sock = NULL;

done:

    if (new_sock)
        free(new_sock);

    return ret;
}

static int _sd_close(libos_sockdev_t* sd, libos_sock_t* sock)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd};
        ECHECK((ret = libos_tcall(SYS_close, params)));
    }

    memset(sock, 0, sizeof(libos_sock_t));
    free(sock);

done:
    return ret;
}

static int _sd_target_fd(libos_sockdev_t* sd, libos_sock_t* sock)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = sock->fd;

done:
    return ret;
}

extern libos_sockdev_t* libos_sockdev_get(void)
{
    // clang-format-off
    static libos_sockdev_t _sockdev = {
        {
            .fd_read = (void*)_sd_read,
            .fd_write = (void*)_sd_write,
            .fd_readv = (void*)_sd_readv,
            .fd_writev = (void*)_sd_writev,
            .fd_fstat = (void*)_sd_fstat,
            .fd_fcntl = (void*)_sd_fcntl,
            .fd_ioctl = (void*)_sd_ioctl,
            .fd_dup = (void*)_sd_dup,
            .fd_close = (void*)_sd_close,
            .fd_target_fd = (void*)_sd_target_fd,
        },
        .sd_socket = _sd_socket,
        .sd_socketpair = _sd_socketpair,
        .sd_connect = _sd_connect,
        .sd_accept = _sd_accept,
        .sd_bind = _sd_bind,
        .sd_listen = _sd_listen,
        .sd_sendto = _sd_sendto,
        .sd_recvfrom = _sd_recvfrom,
        .sd_sendmsg = _sd_sendmsg,
        .sd_recvmsg = _sd_recvmsg,
        .sd_shutdown = _sd_shutdown,
        .sd_getsockopt = _sd_getsockopt,
        .sd_setsockopt = _sd_setsockopt,
        .sd_getpeername = _sd_getpeername,
        .sd_getsockname = _sd_getsockname,
        .sd_read = _sd_read,
        .sd_write = _sd_write,
        .sd_readv = _sd_readv,
        .sd_writev = _sd_writev,
        .sd_fstat = _sd_fstat,
        .sd_fcntl = _sd_fcntl,
        .sd_ioctl = _sd_ioctl,
        .sd_dup = _sd_dup,
        .sd_close = _sd_close,
        .sd_target_fd = _sd_target_fd,
    };
    // clang-format-on

    return &_sockdev;
}
