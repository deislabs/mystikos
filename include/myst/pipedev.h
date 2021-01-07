// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PIPEDEV_H
#define _MYST_PIPEDEV_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <myst/fdops.h>

typedef struct myst_pipedev myst_pipedev_t;

typedef struct myst_pipe myst_pipe_t;

struct myst_pipedev
{
    myst_fdops_t fdops;

    int (*pd_pipe2)(myst_pipedev_t* pipedev, myst_pipe_t* pipe[2], int flags);

    ssize_t (*pd_read)(
        myst_pipedev_t* pipedev,
        myst_pipe_t* pipe,
        void* buf,
        size_t count);

    ssize_t (*pd_write)(
        myst_pipedev_t* pipedev,
        myst_pipe_t* pipe,
        const void* buf,
        size_t count);

    ssize_t (*pd_readv)(
        myst_pipedev_t* pipedev,
        myst_pipe_t* pipe,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*pd_writev)(
        myst_pipedev_t* pipedev,
        myst_pipe_t* pipe,
        const struct iovec* iov,
        int iovcnt);

    int (*pd_fstat)(
        myst_pipedev_t* pipedev,
        myst_pipe_t* pipe,
        struct stat* statbuf);

    int (*pd_fcntl)(
        myst_pipedev_t* pipedev,
        myst_pipe_t* pipe,
        int cmd,
        long arg);

    int (*pd_ioctl)(
        myst_pipedev_t* pipedev,
        myst_pipe_t* pipe,
        unsigned long request,
        long arg);

    int (*pd_dup)(
        myst_pipedev_t* pipedev,
        const myst_pipe_t* pipe,
        myst_pipe_t** pipe_out);

    int (*pd_close)(myst_pipedev_t* pipedev, myst_pipe_t* pipe);

    int (*pd_target_fd)(myst_pipedev_t* pipedev, myst_pipe_t* pipe);

    int (*pd_get_events)(myst_pipedev_t* pipedev, myst_pipe_t* pipe);
};

myst_pipedev_t* myst_pipedev_get(void);

#endif /* _MYST_PIPEDEV_H */
