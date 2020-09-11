// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_BUF_H
#define _LIBOS_BUF_H

#include <libos/types.h>

// clang-format off
#define LIBOS_BUF_INITIALIZER { NULL, 0, 0 }
// clang-format on

typedef struct libos_buf
{
    uint8_t* data;
    size_t size;
    size_t cap;
} libos_buf_t;

void libos_buf_release(libos_buf_t* buf);

int libos_buf_clear(libos_buf_t* buf);

int libos_buf_reserve(libos_buf_t* buf, size_t cap);

int libos_buf_resize(libos_buf_t* buf, size_t new_size);

int libos_buf_append(libos_buf_t* buf, const void* p, size_t size);

int libos_buf_insert(
    libos_buf_t* buf,
    size_t pos,
    const void* data,
    size_t size);

int libos_buf_remove(libos_buf_t* buf, size_t pos, size_t size);

#endif /* _LIBOS_BUF_H */
