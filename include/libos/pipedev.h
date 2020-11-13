// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_PIPEDEV_H
#define _LIBOS_PIPEDEV_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <libos/fdops.h>

typedef struct libos_pipedev libos_pipedev_t;

typedef struct libos_pipe libos_pipe_t;

struct libos_pipedev
{
    libos_fdops_t fdops;

    int (*pd_pipe2)(libos_pipedev_t* pipedev, libos_pipe_t* pipe[2], int flags);

    ssize_t (*pd_read)(
        libos_pipedev_t* pipedev,
        libos_pipe_t* pipe,
        void* buf,
        size_t count);

    ssize_t (*pd_write)(
        libos_pipedev_t* pipedev,
        libos_pipe_t* pipe,
        const void* buf,
        size_t count);

    ssize_t (*pd_readv)(
        libos_pipedev_t* pipedev,
        libos_pipe_t* pipe,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*pd_writev)(
        libos_pipedev_t* pipedev,
        libos_pipe_t* pipe,
        const struct iovec* iov,
        int iovcnt);

    int (*pd_fstat)(
        libos_pipedev_t* pipedev,
        libos_pipe_t* pipe,
        struct stat* statbuf);

    int (*pd_fcntl)(
        libos_pipedev_t* pipedev,
        libos_pipe_t* pipe,
        int cmd,
        long arg);

    int (*pd_ioctl)(
        libos_pipedev_t* pipedev,
        libos_pipe_t* pipe,
        unsigned long request,
        long arg);

    int (*pd_dup)(
        libos_pipedev_t* pipedev,
        const libos_pipe_t* pipe,
        libos_pipe_t** pipe_out);

    int (*pd_close)(libos_pipedev_t* pipedev, libos_pipe_t* pipe);

    int (*pd_target_fd)(libos_pipedev_t* pipedev, libos_pipe_t* pipe);
};

libos_pipedev_t* libos_pipedev_get(void);

#endif /* _LIBOS_PIPEDEV_H */
