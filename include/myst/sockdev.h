// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SOCKDEV_H
#define _MYST_SOCKDEV_H

#include <sys/socket.h>
#include <sys/types.h>

#include <myst/defs.h>
#include <myst/fdops.h>

typedef struct myst_sockdev myst_sockdev_t;

typedef struct myst_sock myst_sock_t;

struct myst_sockdev
{
    myst_fdops_t fdops;

    int (*sd_socket)(
        myst_sockdev_t* sd,
        int domain,
        int type,
        int protocol,
        myst_sock_t** sock);

    int (*sd_socketpair)(
        myst_sockdev_t* sd,
        int domain,
        int type,
        int protocol,
        myst_sock_t* pair[2]);

    int (*sd_connect)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        const struct sockaddr* addr,
        socklen_t addrlen);

    int (*sd_accept4)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        struct sockaddr* addr,
        socklen_t* addrlen,
        int flags,
        myst_sock_t** new_sock);

    int (*sd_bind)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        const struct sockaddr* addr,
        socklen_t addrlen);

    int (*sd_listen)(myst_sockdev_t* sd, myst_sock_t* sock, int backlog);

    ssize_t (*sd_sendto)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        const void* buf,
        size_t len,
        int flags,
        const struct sockaddr* dest_addr,
        socklen_t addrlen);

    ssize_t (*sd_recvfrom)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        void* buf,
        size_t len,
        int flags,
        struct sockaddr* src_addr,
        socklen_t* addrlen);

    int (*sd_sendmsg)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        const struct msghdr* msg,
        int flags);

    int (*sd_recvmsg)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        struct msghdr* msg,
        int flags);

    int (*sd_shutdown)(myst_sockdev_t* sd, myst_sock_t* sock, int how);

    int (*sd_getsockopt)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        int level,
        int optname,
        void* optval,
        socklen_t* optlen);

    int (*sd_setsockopt)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        int level,
        int optname,
        const void* optval,
        socklen_t optlen);

    int (*sd_getpeername)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        struct sockaddr* addr,
        socklen_t* addrlen);

    int (*sd_getsockname)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        struct sockaddr* addr,
        socklen_t* addrlen);

    ssize_t (*sd_read)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        void* buf,
        size_t count);

    ssize_t (*sd_write)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        const void* buf,
        size_t count);

    ssize_t (*sd_readv)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*sd_writev)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        const struct iovec* iov,
        int iovcnt);

    int (
        *sd_fstat)(myst_sockdev_t* sd, myst_sock_t* sock, struct stat* statbuf);

    int (*sd_ioctl)(
        myst_sockdev_t* sd,
        myst_sock_t* sock,
        unsigned long request,
        long arg);

    int (*sd_fcntl)(myst_sockdev_t* sd, myst_sock_t* sock, int cmd, long arg);

    int (*sd_dup)(
        myst_sockdev_t* sd,
        const myst_sock_t* sock,
        myst_sock_t** sock_out);

    int (*sd_close)(myst_sockdev_t* sd, myst_sock_t* sock);

    int (*sd_target_fd)(myst_sockdev_t* sd, myst_sock_t* sock);

    int (*sd_get_events)(myst_sockdev_t* sd, myst_sock_t* sock);
};

myst_sockdev_t* myst_sockdev_get(void);

myst_sockdev_t* myst_udsdev_get(void);

int myst_sockdev_resolve(int domain, int type, myst_sockdev_t** dev);

/*
Input params:
sockfd, sockdev, sock - file descriptor, socket device and object being
reresolved.
addr, addrlen - address being bound(server side) or connected(client
side) to.

Output params:
reresolved - If 'sockdev' is myst kernel udsdev and 'addr' is a hostfs path, set
to true. Otherwise false.

Rest of the output params are only set if 'reresolved' is true.

sockdev_out, sock_out - host socket device and newly created host socket object.
addr_out, addrlen_out - file path in input param 'addr' is a myst internal
path. This function allocates addr_out and maps the file path to the
corresponding host path. This is used subsequent by callers to pass as a
parameter to host socket device function calls - like bind, connect.

*/
int myst_sockdev_reresolve(
    int sockfd,
    myst_sockdev_t* sockdev,
    myst_sock_t* sock,
    const struct sockaddr* addr,
    socklen_t addrlen,
    bool* reresolved,
    myst_sockdev_t** sockdev_out,
    myst_sock_t** sock_out,
    struct sockaddr** addr_out,
    socklen_t* addrlen_out);

const char* myst_socket_type_str(int type);

const char* myst_socket_domain_str(int domain);

const char* myst_format_socket_type(char* buf, size_t len, int type);

#endif /* _MYST_SOCKDEV_H */
