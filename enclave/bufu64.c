// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "bufu64.h"
#include "buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void oel_bufu64_release(oel_bufu64_t* buf)
{
    oel_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);
    oel_buf_release(&tmp);
}

void oel_bufu64_clear(oel_bufu64_t* buf)
{
    oel_bufu64_release(buf);
    buf->data = NULL;
    buf->size = 0;
    buf->cap = 0;
}

int oel_bufu64_append(oel_bufu64_t* buf, const uint64_t* data, size_t size)
{
    oel_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);

    if (oel_buf_append(&tmp, data, size * sizeof(uint64_t)) != 0)
    {
        return -1;
    }

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / sizeof(uint64_t);
    buf->cap = tmp.cap / sizeof(uint64_t);

    return 0;
}

int oel_bufu64_resize(oel_bufu64_t* buf, size_t new_size)
{
    oel_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);

    if (oel_buf_resize(&tmp, new_size * sizeof(uint64_t)) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / sizeof(uint64_t);
    buf->cap = tmp.cap / sizeof(uint64_t);

    return 0;
}

int oel_bufu64_append1(oel_bufu64_t* buf, uint64_t data)
{
    return oel_bufu64_append(buf, &data, 1);
}

int oel_bufu64_remove(oel_bufu64_t* buf, size_t pos, size_t size)
{
    oel_buf_t tmp;

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * sizeof(uint64_t);
    tmp.cap = buf->cap * sizeof(uint64_t);

    pos *= sizeof(uint64_t);
    size *= sizeof(uint64_t);

    if (oel_buf_remove(&tmp, pos, size) != 0)
        return -1;

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / sizeof(uint64_t);
    buf->cap = tmp.cap / sizeof(uint64_t);

    return 0;
}
