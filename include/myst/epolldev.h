// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_EPOLLDEV_H
#define _MYST_EPOLLDEV_H

#include <myst/defs.h>
#include <myst/fdops.h>
#include <sys/epoll.h>

typedef struct myst_epolldev myst_epolldev_t;

typedef struct myst_epoll myst_epoll_t;

struct myst_epolldev
{
    myst_fdops_t fdops;

    int (*ed_epoll_create1)(
        myst_epolldev_t* epolldev,
        int flags,
        myst_epoll_t** epoll);

    int (*ed_epoll_ctl)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        int op,
        int fd,
        struct epoll_event* event);

    int (*ed_epoll_wait)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        struct epoll_event* events,
        int maxevents,
        int timeout);

    ssize_t (*ed_read)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        void* buf,
        size_t count);

    ssize_t (*ed_write)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        const void* buf,
        size_t count);

    ssize_t (*ed_readv)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*ed_writev)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        const struct iovec* iov,
        int iovcnt);

    int (*ed_fstat)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        struct stat* statbuf);

    int (*ed_ioctl)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        unsigned long request,
        long arg);

    int (*ed_fcntl)(
        myst_epolldev_t* epolldev,
        myst_epoll_t* epoll,
        int cmd,
        long arg);

    int (*ed_dup)(
        myst_epolldev_t* epolldev,
        const myst_epoll_t* epoll,
        myst_epoll_t** epoll_out);

    int (*ed_close)(myst_epolldev_t* epolldev, myst_epoll_t* epoll);

    int (*ed_target_fd)(myst_epolldev_t* epolldev, myst_epoll_t* epoll);

    int (*ed_get_events)(myst_epolldev_t* epolldev, myst_epoll_t* epoll);
};

myst_epolldev_t* myst_epolldev_get(void);

#endif /* _MYST_EPOLLDEV_H */
