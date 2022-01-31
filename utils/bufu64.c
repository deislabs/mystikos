// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/buf.h>
#include <myst/bufu64.h>
#include <myst/eraise.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int myst_bufu64_init(myst_bufu64_t* buf, uint64_t* data, size_t size)
{
    if (!buf || (!data && size > 0))
        return -EINVAL;

    buf->data = data;
    buf->size = size;
    buf->cap = size;

    return 0;
}

void myst_bufu64_release(myst_bufu64_t* buf)
{
    myst_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    myst_buf_release(&tmp);
}

int myst_bufu64_reserve(myst_bufu64_t* buf, size_t cap)
{
    int ret = 0;
    myst_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    cap *= n;

    ECHECK(myst_buf_reserve(&tmp, cap));

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

done:
    return ret;
}

int myst_bufu64_resize(myst_bufu64_t* buf, size_t new_size)
{
    int ret = 0;
    myst_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    new_size *= n;

    ECHECK(myst_buf_resize(&tmp, new_size));

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

done:
    return ret;
}

void myst_bufu64_clear(myst_bufu64_t* buf)
{
    myst_bufu64_release(buf);
    buf->data = NULL;
    buf->size = 0;
    buf->cap = 0;
}

int myst_bufu64_append(myst_bufu64_t* buf, const uint64_t* data, size_t size)
{
    int ret = 0;
    myst_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;
    size *= n;

    ECHECK(myst_buf_append(&tmp, data, size));

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

done:
    return ret;
}

int myst_bufu64_append1(myst_bufu64_t* buf, uint64_t data)
{
    return myst_bufu64_append(buf, &data, 1);
}

int myst_bufu64_insert(
    myst_bufu64_t* buf,
    size_t pos,
    const uint64_t* data,
    size_t size)
{
    int ret = 0;
    myst_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;

    pos *= n;
    size *= n;

    ECHECK(myst_buf_insert(&tmp, pos, data, size));

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

done:
    return ret;
}

int myst_bufu64_remove(myst_bufu64_t* buf, size_t pos, size_t size)
{
    int ret = 0;
    myst_buf_t tmp;
    const size_t n = sizeof(uint64_t);

    tmp.data = (uint8_t*)buf->data;
    tmp.size = buf->size * n;
    tmp.cap = buf->cap * n;

    pos *= n;
    size *= n;

    ECHECK(myst_buf_remove(&tmp, pos, size));

    buf->data = (uint64_t*)tmp.data;
    buf->size = tmp.size / n;
    buf->cap = tmp.cap / n;

done:
    return ret;
}
