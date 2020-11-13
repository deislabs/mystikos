// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_BUF_H
#define _LIBOS_BUF_H

#include <libos/types.h>
#include <stdint.h>

// clang-format off
#define LIBOS_BUF_INITIALIZER { NULL, 0, 0, 0 }
// clang-format on

typedef struct libos_buf
{
    uint8_t* data;
    size_t size;
    size_t cap;
    size_t offset;
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

int libos_buf_pack_u64(libos_buf_t* buf, uint64_t x);

int libos_buf_unpack_u64(libos_buf_t* buf, uint64_t* x);

int libos_buf_pack_bytes(libos_buf_t* buf, const void* p, size_t size);

int libos_buf_unpack_bytes(libos_buf_t* buf, const void** p, size_t* size);

int libos_buf_pack_str(libos_buf_t* buf, const char* str);

int libos_buf_unpack_str(libos_buf_t* buf, const char** str, size_t* len);

int libos_buf_pack_strings(
    libos_buf_t* buf,
    const char* strings[],
    size_t count);

int libos_buf_unpack_strings(
    libos_buf_t* buf,
    const char*** strings,
    size_t* count);

#endif /* _LIBOS_BUF_H */
