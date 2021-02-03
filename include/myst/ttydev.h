// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TTYDEV_H
#define _MYST_TTYDEV_H

#include <myst/defs.h>
#include <myst/fdops.h>

typedef struct myst_ttydev myst_ttydev_t;

typedef struct myst_tty myst_tty_t;

struct myst_ttydev
{
    myst_fdops_t fdops;

    int (*td_create)(
        myst_ttydev_t* ttydev,
        int fd, /* STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO */
        myst_tty_t** tty);

    ssize_t (*td_read)(
        myst_ttydev_t* ttydev,
        myst_tty_t* tty,
        void* buf,
        size_t count);

    ssize_t (*td_write)(
        myst_ttydev_t* ttydev,
        myst_tty_t* tty,
        const void* buf,
        size_t count);

    ssize_t (*td_readv)(
        myst_ttydev_t* ttydev,
        myst_tty_t* tty,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*td_writev)(
        myst_ttydev_t* ttydev,
        myst_tty_t* tty,
        const struct iovec* iov,
        int iovcnt);

    int (*td_fstat)(
        myst_ttydev_t* ttydev,
        myst_tty_t* tty,
        struct stat* statbuf);

    int (*td_ioctl)(
        myst_ttydev_t* ttydev,
        myst_tty_t* tty,
        unsigned long request,
        long arg);

    int (*td_fcntl)(myst_ttydev_t* ttydev, myst_tty_t* tty, int cmd, long arg);

    int (*td_dup)(
        myst_ttydev_t* ttydev,
        const myst_tty_t* tty,
        myst_tty_t** tty_out);

    int (*td_close)(myst_ttydev_t* ttydev, myst_tty_t* tty);

    int (*td_target_fd)(myst_ttydev_t* ttydev, myst_tty_t* tty);

    int (*td_get_events)(myst_ttydev_t* ttydev, myst_tty_t* tty);
};

myst_ttydev_t* myst_ttydev_get(void);

#endif /* _MYST_TTYDEV_H */
