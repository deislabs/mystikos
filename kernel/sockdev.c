// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <myst/eraise.h>
#include <myst/iov.h>
#include <myst/panic.h>
#include <myst/sockdev.h>
#include <myst/spinlock.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/printf.h>

#define MAGIC 0xc436d7e6

struct myst_sock
{
    uint32_t magic; /* MAGIC */
    int fd;         /* the target-relative file descriptor */
    bool nonblock;
};

MYST_INLINE bool _valid_sock(const myst_sock_t* sock)
{
    return sock && sock->magic == MAGIC;
}

static void _free_sock(myst_sock_t* sock)
{
    if (sock)
    {
        memset(sock, 0, sizeof(myst_sock_t));
        free(sock);
    }
}

static int _new_sock(myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sock_t* sock = NULL;

    if (!sock_out)
        ERAISE(-EINVAL);

    if (!(sock = calloc(1, sizeof(myst_sock_t))))
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
    myst_sockdev_t* sd,
    int domain,
    int type,
    int protocol,
    myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sock_t* sock = NULL;
    long fd;

    if (sock_out)
        *sock_out = NULL;

    if (!sd || !sock_out)
        ERAISE(-EINVAL);

    ECHECK(_new_sock(&sock));

    /* perform syscall */
    {
        long params[6] = {domain, type, protocol};
        ECHECK(fd = myst_tcall(SYS_socket, params));
    }

    if (type & SOCK_NONBLOCK)
        sock->nonblock = true;

    sock->fd = (int)fd;
    *sock_out = sock;
    sock = NULL;

done:

    if (sock)
        _free_sock(sock);

    return ret;
}

static int _sd_socketpair(
    myst_sockdev_t* sd,
    int domain,
    int type,
    int protocol,
    myst_sock_t* pair[2])
{
    int ret = 0;
    myst_sock_t* sock0 = NULL;
    myst_sock_t* sock1 = NULL;
    int sv[2];

    if (!sd || !pair)
        ERAISE(-EINVAL);

    if (!(sock0 = calloc(1, sizeof(myst_sock_t))))
        ERAISE(-ENOMEM);

    if (!(sock1 = calloc(1, sizeof(myst_sock_t))))
        ERAISE(-ENOMEM);

    /* perform syscall */
    {
        long params[6] = {domain, type, protocol, (long)sv};
        ECHECK(myst_tcall(SYS_socketpair, params));
    }

    if (type & SOCK_NONBLOCK)
    {
        sock0->nonblock = true;
        sock1->nonblock = true;
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
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (sock->nonblock)
        ECHECK(myst_tcall_connect(sock->fd, addr, addrlen));
    else
        ECHECK(myst_tcall_connect_block(sock->fd, addr, addrlen));

done:
    return ret;
}

static int _sd_accept4(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int flags,
    myst_sock_t** new_sock_out)
{
    int ret = 0;
    myst_sock_t* new_sock = NULL;
    int fd;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ECHECK(_new_sock(&new_sock));

    if (sock->nonblock)
    {
        ECHECK(fd = myst_tcall_accept4(sock->fd, addr, addrlen, flags));
    }
    else
    {
        ECHECK(fd = myst_tcall_accept4_block(sock->fd, addr, addrlen, flags));
    }

    if (flags & SOCK_NONBLOCK)
        new_sock->nonblock = true;

    new_sock->fd = fd;
    *new_sock_out = new_sock;
    new_sock = NULL;

done:

    if (new_sock)
        _free_sock(new_sock);

    return ret;
}

static int _sd_bind(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, addrlen};
        ECHECK(myst_tcall(SYS_bind, params));
    }

done:

    return ret;
}

static int _sd_listen(myst_sockdev_t* sd, myst_sock_t* sock, int backlog)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, backlog};
        ECHECK(myst_tcall(SYS_listen, params));
    }

done:

    return ret;
}

static ssize_t _sd_sendto(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (sock->nonblock)
    {
        ECHECK(
            ret = myst_tcall_sendto(
                sock->fd, buf, len, flags, dest_addr, addrlen));
    }
    else
    {
        ECHECK(
            ret = myst_tcall_sendto_block(
                sock->fd, buf, len, flags, dest_addr, addrlen));
    }

done:
    return ret;
}

static ssize_t _sd_recvfrom(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (sock->nonblock)
    {
        ECHECK(
            ret = myst_tcall_recvfrom(
                sock->fd, buf, len, flags, src_addr, addrlen));
    }
    else
    {
        ECHECK(
            ret = myst_tcall_recvfrom_block(
                sock->fd, buf, len, flags, src_addr, addrlen));
    }

done:
    return ret;
}

static int _sd_sendmsg(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    const struct msghdr* msg,
    int flags)
{
    ssize_t ret = 0;
    void* base = NULL;
    size_t len;
    struct iovec iov_buf;
    struct msghdr msg_buf;
    const struct msghdr* msg_ptr;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (!msg)
        ERAISE(-EFAULT);

    if (msg->msg_iovlen < 0 || msg->msg_iovlen > IOV_MAX)
        ERAISE(-EINVAL);

    if (msg->msg_iovlen == 0)
        goto done;

    if (!msg->msg_iov)
        ERAISE(-EINVAL);

    // Pre-flatten the IO vector, else the target will have to use its own
    // memory. Without this, OE heap memory is sometimes depleted by this
    // operation.
    if (msg->msg_iovlen != 1)
    {
        ERAISE((len = myst_iov_gather(msg->msg_iov, msg->msg_iovlen, &base)));
        msg_buf = *msg;
        iov_buf.iov_base = base;
        iov_buf.iov_len = len;
        msg_buf.msg_iov = &iov_buf;
        msg_buf.msg_iovlen = 1;
        msg_ptr = &msg_buf;
    }
    else
    {
        /* The IO vector is already flat */
        msg_ptr = msg;
    }

    if (sock->nonblock)
        ECHECK(ret = myst_tcall_sendmsg(sock->fd, msg_ptr, flags));
    else
        ECHECK(ret = myst_tcall_sendmsg_block(sock->fd, msg_ptr, flags));

done:

    if (base)
        free(base);

    return ret;
}

static int _sd_recvmsg(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    struct msghdr* msg,
    int flags)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (sock->nonblock)
        ECHECK(ret = myst_tcall_recvmsg(sock->fd, msg, flags));
    else
        ECHECK(ret = myst_tcall_recvmsg_block(sock->fd, msg, flags));

done:
    return ret;
}

static int _sd_shutdown(myst_sockdev_t* sd, myst_sock_t* sock, int how)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, how};
        ECHECK(myst_tcall(SYS_shutdown, params));
    }

done:
    return ret;
}

static int _sd_getsockopt(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
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
        ECHECK(myst_tcall(SYS_getsockopt, params));
    }

done:
    return ret;
}

static int _sd_setsockopt(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
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
        ECHECK(myst_tcall(SYS_setsockopt, params));
    }

done:
    return ret;
}

static int _sd_getpeername(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, (long)addrlen};
        ECHECK(myst_tcall(SYS_getpeername, params));
    }

done:
    return ret;
}

static int _sd_getsockname(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)addr, (long)addrlen};
        ECHECK(myst_tcall(SYS_getsockname, params));
    }

done:
    return ret;
}

static ssize_t _sd_read(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (sock->nonblock)
        ECHECK(ret = myst_tcall_read(sock->fd, buf, count));
    else
        ECHECK(ret = myst_tcall_read_block(sock->fd, buf, count));

done:
    return ret;
}

static ssize_t _sd_write(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (sock->nonblock)
        ECHECK(ret = myst_tcall_write_block(sock->fd, buf, count));
    else
        ECHECK(ret = myst_tcall_write(sock->fd, buf, count));

done:
    return ret;
}

static ssize_t _sd_readv(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = myst_fdops_readv(&sd->fdops, sock, iov, iovcnt);
    ECHECK(ret);

done:
    return ret;
}

static ssize_t _sd_writev(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&sd->fdops, sock, iov, iovcnt);
    ECHECK(ret);

done:
    return ret;
}

static int _sd_fstat(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    struct stat* statbuf)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd, (long)statbuf};
        ECHECK(myst_tcall(SYS_fstat, params));
    }

done:
    return ret;
}

static int _sd_ioctl(
    myst_sockdev_t* sd,
    myst_sock_t* sock,
    unsigned long request,
    long arg)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (request == FIONBIO)
    {
        int* val = (int*)arg;

        if (!val)
            ERAISE(-EINVAL);

        sock->nonblock = (bool)*val;
        goto done;
    }

    /* perform syscall */
    {
        long params[6] = {sock->fd, request, arg};
        ECHECK(myst_tcall(SYS_ioctl, params));
    }

done:
    return ret;
}

static int _sd_fcntl(myst_sockdev_t* sd, myst_sock_t* sock, int cmd, long arg)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    if (cmd == F_SETFL)
    {
        if ((arg & O_NONBLOCK))
        {
            sock->nonblock = true;
        }
        else
        {
            sock->nonblock = false;
            /* target sockets are always non-blocking */
            arg |= O_NONBLOCK;
        }
    }

    /* perform syscall */
    {
        long params[6] = {sock->fd, cmd, arg};
        ECHECK((ret = myst_tcall(SYS_fcntl, params)));
    }

    if (cmd == F_GETFL)
    {
        if (sock->nonblock)
            ret |= O_NONBLOCK;
        else
            ret &= ~O_NONBLOCK;
    }

done:
    return ret;
}

static int _sd_dup(
    myst_sockdev_t* sd,
    const myst_sock_t* sock,
    myst_sock_t** sock_out)
{
    int ret = 0;
    myst_sock_t* new_sock = NULL;
    long fd;

    if (sock_out)
        *sock_out = NULL;

    if (!sd || !_valid_sock(sock) || !sock_out)
        ERAISE(-EINVAL);

    if (!(new_sock = calloc(1, sizeof(myst_sock_t))))
        ERAISE(-ENOMEM);

    /* perform syscall */
    {
        long params[6] = {sock->fd};
        ECHECK((fd = myst_tcall(SYS_dup, params)));
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

static int _sd_close(myst_sockdev_t* sd, myst_sock_t* sock)
{
    ssize_t ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    /* perform syscall */
    {
        long params[6] = {sock->fd};
        ECHECK((ret = myst_tcall(SYS_close, params)));
    }

    memset(sock, 0, sizeof(myst_sock_t));
    free(sock);

done:
    return ret;
}

static int _sd_target_fd(myst_sockdev_t* sd, myst_sock_t* sock)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = sock->fd;

done:
    return ret;
}

static int _sd_get_events(myst_sockdev_t* sd, myst_sock_t* sock)
{
    int ret = 0;

    if (!sd || !_valid_sock(sock))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

myst_sockdev_t* myst_sockdev_get(int sock_domain, int sock_type)
{
    // clang-format-off
    static myst_sockdev_t _sockdev = {
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
            .fd_get_events = (void*)_sd_get_events,
        },
        .sd_socket = _sd_socket,
        .sd_socketpair = _sd_socketpair,
        .sd_connect = _sd_connect,
        .sd_accept4 = _sd_accept4,
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
        .sd_get_events = _sd_get_events,
    };
    // clang-format-on

    if (sock_domain != AF_INET && sock_domain != AF_INET6)
    {
        myst_eprintf("kernel: warning: unsupported socket domain: %u\n",
            sock_domain);
        return NULL;
    }

    if (!(sock_type & SOCK_STREAM) && !(sock_type & SOCK_DGRAM))
    {
        myst_eprintf("kernel: warning: unsupported socket type: %u\n",
            sock_type);
        return NULL;
    }

    return &_sockdev;
}
