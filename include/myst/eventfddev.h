// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_EVENTFDDEV_H
#define _MYST_EVENTFDDEV_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <myst/fdops.h>

typedef struct myst_eventfddev myst_eventfddev_t;

typedef struct myst_eventfd myst_eventfd_t;

struct myst_eventfddev
{
    myst_fdops_t fdops;

    int (*eventfd)(
        myst_eventfddev_t* eventfddev,
        unsigned int intval,
        int flags,
        myst_eventfd_t** eventfd_out);

    ssize_t (*read)(
        myst_eventfddev_t* eventfddev,
        myst_eventfd_t* eventfd,
        void* buf,
        size_t count);

    ssize_t (*write)(
        myst_eventfddev_t* eventfddev,
        myst_eventfd_t* eventfd,
        const void* buf,
        size_t count);

    ssize_t (*readv)(
        myst_eventfddev_t* eventfddev,
        myst_eventfd_t* eventfd,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*writev)(
        myst_eventfddev_t* eventfddev,
        myst_eventfd_t* eventfd,
        const struct iovec* iov,
        int iovcnt);

    int (*fstat)(
        myst_eventfddev_t* eventfddev,
        myst_eventfd_t* eventfd,
        struct stat* statbuf);

    int (*fcntl)(
        myst_eventfddev_t* eventfddev,
        myst_eventfd_t* eventfd,
        int cmd,
        long arg);

    int (*ioctl)(
        myst_eventfddev_t* eventfddev,
        myst_eventfd_t* eventfd,
        unsigned long request,
        long arg);

    int (*dup)(
        myst_eventfddev_t* eventfddev,
        const myst_eventfd_t* eventfd,
        myst_eventfd_t** eventfd_out);

    int (*close)(myst_eventfddev_t* eventfddev, myst_eventfd_t* eventfd);

    int (*target_fd)(myst_eventfddev_t* eventfddev, myst_eventfd_t* eventfd);

    int (*get_events)(myst_eventfddev_t* eventfddev, myst_eventfd_t* eventfd);
};

myst_eventfddev_t* myst_eventfddev_get(void);

#endif /* _MYST_EVENTFDDEV_H */
