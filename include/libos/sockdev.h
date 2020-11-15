// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_SOCKDEV_H
#define _LIBOS_SOCKDEV_H

#include <sys/socket.h>
#include <sys/types.h>

#include <libos/defs.h>
#include <libos/fdops.h>

typedef struct libos_sockdev libos_sockdev_t;

typedef struct libos_sock libos_sock_t;

struct libos_sockdev
{
    libos_fdops_t fdops;

    int (*sd_socket)(
        libos_sockdev_t* sd,
        int domain,
        int type,
        int protocol,
        libos_sock_t** sock);

    int (*sd_socketpair)(
        libos_sockdev_t* sd,
        int domain,
        int type,
        int protocol,
        libos_sock_t* pair[2]);

    int (*sd_connect)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        const struct sockaddr* addr,
        socklen_t addrlen);

    int (*sd_accept)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        struct sockaddr* addr,
        socklen_t* addrlen,
        libos_sock_t** new_sock);

    int (*sd_bind)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        const struct sockaddr* addr,
        socklen_t addrlen);

    int (*sd_listen)(libos_sockdev_t* sd, libos_sock_t* sock, int backlog);

    ssize_t (*sd_sendto)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        const void* buf,
        size_t len,
        int flags,
        const struct sockaddr* dest_addr,
        socklen_t addrlen);

    ssize_t (*sd_recvfrom)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        void* buf,
        size_t len,
        int flags,
        struct sockaddr* src_addr,
        socklen_t* addrlen);

    int (*sd_sendmsg)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        const struct msghdr* msg,
        int flags);

    int (*sd_recvmsg)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        struct msghdr* msg,
        int flags);

    int (*sd_shutdown)(libos_sockdev_t* sd, libos_sock_t* sock, int how);

    int (*sd_getsockopt)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        int level,
        int optname,
        void* optval,
        socklen_t* optlen);

    int (*sd_setsockopt)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        int level,
        int optname,
        const void* optval,
        socklen_t optlen);

    int (*sd_getpeername)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        struct sockaddr* addr,
        socklen_t* addrlen);

    int (*sd_getsockname)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        struct sockaddr* addr,
        socklen_t* addrlen);

    ssize_t (*sd_read)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        void* buf,
        size_t count);

    ssize_t (*sd_write)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        const void* buf,
        size_t count);

    ssize_t (*sd_readv)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*sd_writev)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        const struct iovec* iov,
        int iovcnt);

    int (*sd_fstat)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        struct stat* statbuf);

    int (*sd_ioctl)(
        libos_sockdev_t* sd,
        libos_sock_t* sock,
        unsigned long request,
        long arg);

    int (*sd_fcntl)(libos_sockdev_t* sd, libos_sock_t* sock, int cmd, long arg);

    int (*sd_dup)(
        libos_sockdev_t* sd,
        const libos_sock_t* sock,
        libos_sock_t** sock_out);

    int (*sd_close)(libos_sockdev_t* sd, libos_sock_t* sock);

    int (*sd_target_fd)(libos_sockdev_t* sd, libos_sock_t* sock);

    int (*sd_get_events)(libos_sockdev_t* sd, libos_sock_t* sock);
};

libos_sockdev_t* libos_sockdev_get(void);

#endif /* _LIBOS_SOCKDEV_H */
