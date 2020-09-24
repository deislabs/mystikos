// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <libos/buf.h>
#include <libos/bufu64.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int libos_bufu64_init(libos_bufu64_t* buf, uint64_t* data, size_t size)
{
    if (!buf || (!data && size > 0))
        return -1;

    buf->data = data;
    buf->size = size;
    buf->cap = size;

    return 0;
}

void libos_bufu64_release(libos_bufu64_t* buf)
{
    libos_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    libos_buf_release(&tmp);
}

int libos_bufu64_reserve(libos_bufu64_t* buf, size_t cap)
{
    libos_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    cap *= n;

    if (libos_buf_reserve(&tmp, cap) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

    return 0;
}

int libos_bufu64_resize(libos_bufu64_t* buf, size_t new_size)
{
    libos_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    new_size *= n;

    if (libos_buf_resize(&tmp, new_size) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

    return 0;
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
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    size *= n;

    if (libos_buf_append(&tmp, data, size) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

    return 0;
}

int libos_bufu64_append1(libos_bufu64_t* buf, uint64_t data)
{
    return libos_bufu64_append(buf, &data, 1);
}

int libos_bufu64_insert(
    libos_bufu64_t* buf,
    size_t pos,
    const uint64_t* data,
    size_t size)
{
    libos_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;

    pos *= n;
    size *= n;

    if (libos_buf_insert(&tmp, pos, data, size) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

    return 0;
}

int libos_bufu64_remove(libos_bufu64_t* buf, size_t pos, size_t size)
{
    libos_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;

    pos *= n;
    size *= n;

    if (libos_buf_remove(&tmp, pos, size) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

    return 0;
}
