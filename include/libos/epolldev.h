// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_EPOLLDEV_H
#define _LIBOS_EPOLLDEV_H

#include <libos/defs.h>
#include <libos/fdops.h>
#include <sys/epoll.h>

typedef struct libos_epolldev libos_epolldev_t;

typedef struct libos_epoll libos_epoll_t;

struct libos_epolldev
{
    libos_fdops_t fdops;

    int (*ed_epoll_create1)(
        libos_epolldev_t* epolldev,
        int flags,
        libos_epoll_t** epoll);

    int (*ed_epoll_ctl)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        int op,
        int fd,
        struct epoll_event* event);

    int (*ed_epoll_wait)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        struct epoll_event* events,
        int maxevents,
        int timeout);

    ssize_t (*ed_read)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        void* buf,
        size_t count);

    ssize_t (*ed_write)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        const void* buf,
        size_t count);

    ssize_t (*ed_readv)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*ed_writev)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        const struct iovec* iov,
        int iovcnt);

    int (*ed_fstat)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        struct stat* statbuf);

    int (*ed_ioctl)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        unsigned long request,
        long arg);

    int (*ed_fcntl)(
        libos_epolldev_t* epolldev,
        libos_epoll_t* epoll,
        int cmd,
        long arg);

    int (*ed_dup)(
        libos_epolldev_t* epolldev,
        const libos_epoll_t* epoll,
        libos_epoll_t** epoll_out);

    int (*ed_close)(libos_epolldev_t* epolldev, libos_epoll_t* epoll);

    int (*ed_target_fd)(libos_epolldev_t* epolldev, libos_epoll_t* epoll);

    int (*ed_get_events)(libos_epolldev_t* epolldev, libos_epoll_t* epoll);
};

libos_epolldev_t* libos_epolldev_get(void);

#endif /* _LIBOS_EPOLLDEV_H */
