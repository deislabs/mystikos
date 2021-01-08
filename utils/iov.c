#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <myst/iov.h>

ssize_t myst_iov_len(const struct iovec* iov, int iovcnt)
{
    ssize_t ret = 0;
    ssize_t size = 0;

    if (!iov)
    {
        ret = -EINVAL;
        goto done;
    }

    for (int i = 0; i < iovcnt; i++)
    {
        const struct iovec* v = &iov[i];

        if (!v->iov_base && v->iov_len)
        {
            ret = -EINVAL;
            goto done;
        }

        size += v->iov_len;
    }

    ret = size;

done:
    return ret;
}

ssize_t myst_iov_gather(const struct iovec* iov, int iovcnt, void** buf_out)
{
    ssize_t ret = 0;
    ssize_t len = 0;
    void* buf = NULL;

    if (buf_out)
        *buf_out = NULL;

    if (!iov || iovcnt < 0 || !buf_out)
    {
        ret = -EINVAL;
        goto done;
    }

    /* calculate the length of the flat output buffer */
    if ((len = myst_iov_len(iov, iovcnt)) < 0)
    {
        ret = len;
        goto done;
    }

    /* succeed if zero bytes to write (leaving buffer null) */
    if (len == 0)
    {
        ret = 0;
        goto done;
    }

    /* allocate the flat output buffer */
    if (!(buf = malloc(len)))
    {
        ret = -ENOMEM;
        goto done;
    }

    /* copy iov onto flat buffer */
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

    *buf_out = buf;
    buf = NULL;
    ret = len;

done:

    if (buf)
        free(buf);

    return ret;
}

long myst_iov_scatter(
    const struct iovec* iov,
    int iovcnt,
    const void* buf,
    size_t len)
{
    long ret = 0;
    const uint8_t* ptr = buf;
    size_t rem = len;

    if (!iov || (!buf && len))
    {
        ret = -EINVAL;
        goto done;
    }

    for (int i = 0; i < iovcnt && rem; i++)
    {
        const struct iovec* v = &iov[i];

        if (!v->iov_base && v->iov_len)
        {
            ret = -EINVAL;
            goto done;
        }

        if (v->iov_len)
        {
            size_t min = (rem < v->iov_len) ? rem : v->iov_len;
            memcpy(v->iov_base, ptr, min);
            ptr += min;
            rem -= min;
        }
    }

    if (rem != 0)
    {
        ret = -ENOMEM;
        goto done;
    }

done:
    return ret;
}
