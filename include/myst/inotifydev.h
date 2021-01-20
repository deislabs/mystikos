// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_INOTIFYDEV_H
#define _MYST_INOTIFYDEV_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <myst/fdops.h>

typedef struct myst_inotifydev myst_inotifydev_t;

typedef struct myst_inotify myst_inotify_t;

struct myst_inotifydev
{
    myst_fdops_t fdops;

    int (*id_inotify_init1)(
        myst_inotifydev_t* dev,
        int flags,
        myst_inotify_t** obj);

    ssize_t (*id_read)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        void* buf,
        size_t count);

    ssize_t (*id_write)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        const void* buf,
        size_t count);

    ssize_t (*id_readv)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*id_writev)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        const struct iovec* iov,
        int iovcnt);

    int (*id_fstat)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        struct stat* statbuf);

    int (*id_fcntl)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        int cmd,
        long arg);

    int (*id_ioctl)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        unsigned long request,
        long arg);

    int (*id_dup)(
        myst_inotifydev_t* dev,
        const myst_inotify_t* obj,
        myst_inotify_t** inotify_out);

    int (*id_close)(myst_inotifydev_t* dev, myst_inotify_t* obj);

    int (*id_target_fd)(myst_inotifydev_t* dev, myst_inotify_t* obj);

    int (*id_get_events)(myst_inotifydev_t* dev, myst_inotify_t* obj);

    int (*id_inotify_add_watch)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        const char* pathname,
        uint32_t mask);

    int (*id_inotify_rm_watch)(
        myst_inotifydev_t* dev,
        myst_inotify_t* obj,
        int wd);
};

myst_inotifydev_t* myst_inotifydev_get(void);

#endif /* _MYST_INOTIFYDEV_H */
