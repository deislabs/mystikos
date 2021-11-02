// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myst/args.h>
#include <myst/buf.h>
#include <myst/bufu64.h>
#include <myst/errno.h>

#define CAP 16

MYST_INLINE myst_bufu64_t _to_buf(const myst_args_t* args)
{
    myst_bufu64_t ret;

    ret.data = (uint64_t*)args->data;
    ret.size = args->size + 1;
    ret.cap = args->cap + 1;

    return ret;
}

MYST_INLINE myst_args_t _to_args(const myst_bufu64_t* buf)
{
    myst_args_t ret;

    ret.data = (const char**)buf->data;
    ret.size = buf->size - 1;
    ret.cap = buf->cap - 1;

    return ret;
}

int myst_args_init(myst_args_t* self)
{
    if (!self)
        return -1;

    /* allocate an extra entry for the null terminator */
    if (!(self->data = calloc(CAP + 1, sizeof(char*))))
        return -1;

    self->size = 0;
    self->cap = CAP;

    return 0;
}

int myst_args_adopt(myst_args_t* self, const char** data, size_t size)
{
    if (!self || !data)
        return -1;

    /* none of the strings may be null */
    for (size_t i = 0; i < size; i++)
    {
        if (!data[i])
            return -1;
    }

    /* check for null terminator */
    if (data[size])
        return -1;

    self->data = data;
    self->size = size;
    self->cap = size;

    return 0;
}

void myst_args_release(myst_args_t* self)
{
    if (self && self->data)
        free(self->data);
}

int myst_args_reserve(myst_args_t* self, size_t cap)
{
    myst_bufu64_t buf = _to_buf(self);

    if (!self)
        return -1;

    cap++;

    if (myst_bufu64_reserve(&buf, cap) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int myst_args_append(myst_args_t* self, const char** data, size_t size)
{
    myst_bufu64_t buf = _to_buf(self);

    if (!self || (!data && size))
        return -1;

    if (size == 0)
        return 0;

    /* insert right before the null terminator */
    if (myst_bufu64_insert(&buf, self->size, (const uint64_t*)data, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int myst_args_append1(myst_args_t* self, const char* data)
{
    myst_bufu64_t buf = _to_buf(self);

    if (!self || !data)
        return -1;

    /* insert right before the null terminator */
    if (myst_bufu64_insert(&buf, self->size, (const uint64_t*)&data, 1) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int myst_args_prepend(myst_args_t* self, const char** data, size_t size)
{
    myst_bufu64_t buf = _to_buf(self);

    if (!self || !data)
        return -1;

    if (size == 0)
        return 0;

    /* insert right before the null terminator */
    if (myst_bufu64_insert(&buf, 0, (const uint64_t*)data, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int myst_args_prepend1(myst_args_t* self, const char* data)
{
    myst_bufu64_t buf = _to_buf(self);

    if (!self || !data)
        return -1;

    /* insert right before the null terminator */
    if (myst_bufu64_insert(&buf, 0, (const uint64_t*)&data, 1) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int myst_args_insert(
    myst_args_t* self,
    size_t pos,
    const char** data,
    size_t size)
{
    myst_bufu64_t buf = _to_buf(self);

    if (!self || !data || pos > size)
        return -1;

    if (size == 0)
        return 0;

    if (myst_bufu64_insert(&buf, pos, (const uint64_t*)data, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int myst_args_remove(myst_args_t* self, size_t pos, size_t size)
{
    myst_bufu64_t buf = _to_buf(self);

    if (!self || pos + size > self->size)
        return -1;

    if (myst_bufu64_remove(&buf, pos, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int myst_args_pack(
    const myst_args_t* self,
    void** packed_data,
    size_t* packed_size)
{
    int ret = -1;
    myst_buf_t buf = MYST_BUF_INITIALIZER;

    if (!self || !packed_data || !packed_size)
        goto done;

    if (!self->data)
        goto done;

    if (myst_buf_pack_strings(&buf, self->data, self->size) != 0)
        goto done;

    *packed_data = buf.data;
    *packed_size = buf.size;

    ret = 0;

done:
    return ret;
}

int myst_args_unpack(
    myst_args_t* self,
    const void* packed_data,
    size_t packed_size)
{
    myst_buf_t buf;
    buf.data = (uint8_t*)packed_data;
    buf.size = packed_size;
    buf.cap = packed_size;
    buf.offset = 0;
    const char** data;
    size_t size;

    if (!self || !packed_data || !packed_size)
        return 0;

    if (myst_buf_unpack_strings(&buf, &data, &size) != 0)
        return -1;

    self->data = data;
    self->size = size;
    self->cap = size;

    return 0;
}

void myst_args_dump(myst_args_t* self)
{
    if (!self)
        return;

    printf("==== myst_args_dump()\n");

    for (size_t i = 0; i < self->size; i++)
    {
        printf("data[%zu]=%s\n", i, self->data[i]);
    }

    printf("data[%zu]=%s\n", self->size, self->data[self->size]);
    printf("\n");
}

/* looks at the first n chars and returns pos if found, else returns -ENOENT */
int myst_args_find(myst_args_t* self, const char* data, size_t n)
{
    if (!self || !data)
        return -1;

    size_t i = 0;
    for (i = 0; i < self->size; i++)
    {
        if (self->data[i] && strncmp(self->data[i], data, n) == 0)
        {
            return i;
        }
    }

    return -ENOENT;
}
