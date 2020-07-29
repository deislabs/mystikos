// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OEL_BUF_H
#define _OEL_BUF_H

#include <stddef.h>
#include <stdint.h>

#define OEL_BUF_INITIALIZER \
    {                   \
        NULL, 0, 0      \
    }

typedef struct _oel_buf
{
    void* data;
    size_t size;
    size_t cap;
} oel_buf_t;

void oel_buf_release(oel_buf_t* buf);

int oel_buf_clear(oel_buf_t* buf);

int oel_buf_reserve(oel_buf_t* buf, size_t cap);

int oel_buf_resize(oel_buf_t* buf, size_t new_size);

int oel_buf_append(oel_buf_t* buf, const void* data, size_t size);

#endif /* _OEL_BUF_H */
