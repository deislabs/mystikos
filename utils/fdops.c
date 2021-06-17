// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <myst/eraise.h>
#include <myst/fdops.h>

#define SCRATCH_BUF_SIZE 256

static ssize_t _get_iov_size(const struct iovec* iov, int iovcnt)
{
    ssize_t ret = 0;
    ssize_t size = 0;

    for (int i = 0; i < iovcnt; i++)
    {
        const struct iovec* v = &iov[i];

        if (!v->iov_base && v->iov_len)
            ERAISE(-EINVAL);

        if (v->iov_len == (size_t)-1)
            ERAISE(-EINVAL);

        size += v->iov_len;
    }

    ret = size;

done:
    return ret;
}

ssize_t myst_fdops_readv(
    myst_fdops_t* fdops,
    void* object,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    ssize_t count = 0;
    uint8_t scratch[SCRATCH_BUF_SIZE];
    void* buf = NULL;
    ssize_t r;

    if (!fdops || (!iov && iovcnt) || iovcnt < 0)
        ERAISE(-EINVAL);

    /* Calculate the number of bytes to read */
    ECHECK(count = _get_iov_size(iov, iovcnt));

    /* suceed if zero bytes to read */
    if (count == 0)
        goto done;

    /* choose between the scratch buffer and the dynamic buffer */
    if ((size_t)count <= sizeof(scratch))
        buf = scratch;
    else if (!(buf = malloc(count)))
        ERAISE(-ENOMEM);

    /* Peform the read */
    if ((r = (*fdops->fd_read)(fdops, object, buf, count)) < 0)
        ERAISE(r);

    /* Copy the data back to the caller's buffer */
    {
        const uint8_t* ptr = buf;
        size_t rem = r;

        for (int i = 0; i < iovcnt && rem; i++)
        {
            const struct iovec* v = &iov[i];

            if (v->iov_len)
            {
                size_t min = (rem < v->iov_len) ? rem : v->iov_len;
                memcpy(v->iov_base, ptr, min);
                ptr += min;
                rem -= min;
            }
        }
    }

    ret = r;

done:

    if (buf != scratch)
        free(buf);

    return ret;
}

ssize_t myst_fdops_writev(
    myst_fdops_t* fdops,
    void* object,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    ssize_t count = 0;
    uint8_t scratch[SCRATCH_BUF_SIZE];
    void* buf = NULL;
    ssize_t r;

    if (!fdops || (!iov && iovcnt) || iovcnt < 0)
        ERAISE(-EINVAL);

    /* Calculate the number of bytes to write */
    ECHECK(count = _get_iov_size(iov, iovcnt));

    /* suceed if zero bytes to write */
    if (count == 0)
        goto done;

    /* choose between the scratch buffer and the dynamic buffer */
    if ((size_t)count <= sizeof(scratch))
        buf = scratch;
    else if (!(buf = malloc(count)))
        ERAISE(-ENOMEM);

    /* Copy the caller buffer onto the flat buffer */
    {
        uint8_t* ptr = buf;

        for (int i = 0; i < iovcnt; i++)
        {
            const struct iovec* v = &iov[i];

            if (v->iov_len)
            {
                memcpy(ptr, v->iov_base, v->iov_len);
                ptr += v->iov_len;
            }
        }
    }

    /* Peform the write */
    if ((r = (*fdops->fd_write)(fdops, object, buf, count)) < 0)
        ERAISE(r);

    ret = r;

done:

    if (buf != scratch)
        free(buf);

    return ret;
}
