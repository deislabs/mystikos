// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_IOV_H
#define _LIBOS_IOV_H

#include <sys/uio.h>

ssize_t libos_iov_len(const struct iovec* iov, int iovcnt);

ssize_t libos_iov_gather(const struct iovec* iov, int iovcnt, void** buf);

long libos_iov_scatter(
    const struct iovec* iov,
    int iovcnt,
    const void* buf,
    size_t len);

#endif /* _LIBOS_IOV_H */
