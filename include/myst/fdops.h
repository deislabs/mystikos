// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FDOPS_H
#define _MYST_FDOPS_H

#include <stddef.h>
#include <sys/stat.h>
#include <sys/uio.h>

typedef struct myst_fdops myst_fdops_t;

struct myst_fdops
{
    ssize_t (*fd_read)(void* device, void* object, void* buf, size_t count);

    ssize_t (
        *fd_write)(void* device, void* object, const void* buf, size_t count);

    ssize_t (*fd_readv)(
        void* device,
        void* object,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*fd_writev)(
        void* device,
        void* object,
        const struct iovec* iov,
        int iovcnt);

    int (*fd_fstat)(void* device, void* object, struct stat* statbuf);

    int (*fd_fcntl)(void* device, void* object, int cmd, long arg);

    int (
        *fd_ioctl)(void* device, void* object, unsigned long request, long arg);

    int (*fd_dup)(void* device, void* object, void** object_out);

    int (*fd_close)(void* device, void* object);

    int (*fd_target_fd)(void* device, void* object);

    /* returns POLLIN | POLLOUT | POLLERR */
    int (*fd_get_events)(void* device, void* object);
};

ssize_t myst_fdops_readv(
    myst_fdops_t* fdops,
    void* object,
    const struct iovec* iov,
    int iovcnt);

ssize_t myst_fdops_writev(
    myst_fdops_t* fdops,
    void* object,
    const struct iovec* iov,
    int iovcnt);

#endif /* _MYST_FDOPS_H */
