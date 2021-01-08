// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_IOV_H
#define _MYST_IOV_H

#include <sys/uio.h>

ssize_t myst_iov_len(const struct iovec* iov, int iovcnt);

ssize_t myst_iov_gather(const struct iovec* iov, int iovcnt, void** buf);

long myst_iov_scatter(
    const struct iovec* iov,
    int iovcnt,
    const void* buf,
    size_t len);

#endif /* _MYST_IOV_H */
