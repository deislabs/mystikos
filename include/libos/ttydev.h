// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_TTYDEV_H
#define _LIBOS_TTYDEV_H

#include <libos/defs.h>
#include <libos/fdops.h>

typedef struct libos_ttydev libos_ttydev_t;

typedef struct libos_tty libos_tty_t;

struct libos_ttydev
{
    libos_fdops_t fdops;

    int (*td_create)(
        libos_ttydev_t* ttydev,
        int fd, /* STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO */
        libos_tty_t** tty);

    ssize_t (*td_read)(
        libos_ttydev_t* ttydev,
        libos_tty_t* tty,
        void* buf,
        size_t count);

    ssize_t (*td_write)(
        libos_ttydev_t* ttydev,
        libos_tty_t* tty,
        const void* buf,
        size_t count);

    ssize_t (*td_readv)(
        libos_ttydev_t* ttydev,
        libos_tty_t* tty,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*td_writev)(
        libos_ttydev_t* ttydev,
        libos_tty_t* tty,
        const struct iovec* iov,
        int iovcnt);

    int (*td_fstat)(
        libos_ttydev_t* ttydev,
        libos_tty_t* tty,
        struct stat* statbuf);

    int (*td_ioctl)(
        libos_ttydev_t* ttydev,
        libos_tty_t* tty,
        unsigned long request,
        long arg);

    int (
        *td_fcntl)(libos_ttydev_t* ttydev, libos_tty_t* tty, int cmd, long arg);

    int (*td_dup)(
        libos_ttydev_t* ttydev,
        const libos_tty_t* tty,
        libos_tty_t** tty_out);

    int (*td_close)(libos_ttydev_t* ttydev, libos_tty_t* tty);

    int (*td_target_fd)(libos_ttydev_t* ttydev, libos_tty_t* tty);
};

libos_ttydev_t* libos_ttydev_get(void);

#endif /* _LIBOS_TTYDEV_H */
