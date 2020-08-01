// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIBOS_BUF_CHUNK_SIZE 1024

void libos_buf_release(libos_buf_t* buf)
{
    if (buf && buf->data)
    {
        memset(buf->data, 0xDD, buf->size);
        free(buf->data);
    }

    memset(buf, 0x00, sizeof(libos_buf_t));
}

int libos_buf_clear(libos_buf_t* buf)
{
    if (!buf)
        return -1;

    buf->size = 0;

    return 0;
}

int libos_buf_reserve(libos_buf_t* buf, size_t cap)
{
    if (!buf)
        return -1;

    /* If capacity is bigger than current capacity */
    if (cap > buf->cap)
    {
        void* new_data;
        size_t new_cap;

        /* Double current capacity (will be zero the first time) */
        new_cap = buf->cap * 2;

        /* If capacity still insufficent, round to multiple of chunk size */
        if (cap > new_cap)
        {
            const size_t N = LIBOS_BUF_CHUNK_SIZE;
            new_cap = (cap + N - 1) / N * N;
        }

        /* Expand allocation */
        if (!(new_data = realloc(buf->data, new_cap)))
            return -1;

        buf->data = new_data;
        buf->cap = new_cap;
    }

    return 0;
}

int libos_buf_resize(libos_buf_t* buf, size_t new_size)
{
    uint8_t* data;

    if (!buf)
        return -1;

    if (new_size == 0)
    {
        libos_buf_release(buf);
        memset(buf, 0, sizeof(libos_buf_t));
        return 0;
    }

    if (!(data = realloc(buf->data, new_size)))
        return -1;

    if (new_size > buf->size)
        memset(data + buf->size, 0, new_size - buf->size);

    buf->data = data;
    buf->size = new_size;
    buf->cap = new_size;

    return 0;
}

int libos_buf_append(libos_buf_t* buf, const void* data, size_t size)
{
    size_t new_size;

    /* Check arguments */
    if (!buf || !data)
        return -1;

    /* If zero-sized, then success */
    if (size == 0)
        return 0;

    /* Compute the new size */
    new_size = buf->size + size;

    /* If insufficient capacity to hold new data */
    if (new_size > buf->cap)
    {
        int err;

        if ((err = libos_buf_reserve(buf, new_size)) != 0)
            return err;
    }

    /* Copy the data */
    memcpy(buf->data + buf->size, data, size);
    buf->size = new_size;

    return 0;
}

int libos_buf_remove(libos_buf_t* buf, size_t pos, size_t size)
{
    size_t rem;

    if (!buf || pos > buf->size || pos + size > buf->size)
        return -1;

    rem = buf->size - pos;

    if (rem)
        memmove(buf->data + pos, buf->data + pos + size, rem);

    buf->size -= size;

    return 0;
}
