// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "bufu64.h"
#include "buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void libos_bufu64_release(libos_bufu64_t* buf)
{
    libos_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);
    libos_buf_release(&tmp);
}

void libos_bufu64_clear(libos_bufu64_t* buf)
{
    libos_bufu64_release(buf);
    buf->data = NULL;
    buf->size = 0;
    buf->cap = 0;
}

int libos_bufu64_append(libos_bufu64_t* buf, const uint64_t* data, size_t size)
{
    libos_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);

    if (libos_buf_append(&tmp, data, size * sizeof(uint64_t)) != 0)
    {
        return -1;
    }

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / sizeof(uint64_t);
    buf->cap = tmp.cap / sizeof(uint64_t);

    return 0;
}

int libos_bufu64_resize(libos_bufu64_t* buf, size_t new_size)
{
    libos_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);

    if (libos_buf_resize(&tmp, new_size * sizeof(uint64_t)) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / sizeof(uint64_t);
    buf->cap = tmp.cap / sizeof(uint64_t);

    return 0;
}

int libos_bufu64_append1(libos_bufu64_t* buf, uint64_t data)
{
    return libos_bufu64_append(buf, &data, 1);
}

int libos_bufu64_remove(libos_bufu64_t* buf, size_t pos, size_t size)
{
    libos_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);

    pos *= sizeof(uint64_t);
    size *= sizeof(uint64_t);

    if (libos_buf_remove(&tmp, pos, size) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / sizeof(uint64_t);
    buf->cap = tmp.cap / sizeof(uint64_t);

    return 0;
}
