// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BUF_H
#define _MYST_BUF_H

#include <myst/types.h>
#include <stdint.h>

// clang-format off
#define MYST_BUF_INITIALIZER { NULL, 0, 0, 0, 0 }
// clang-format on

#define MYST_BUF_PAGE_ALIGNED 1
typedef struct myst_buf
{
    uint8_t* data;
    size_t size;
    size_t cap;
    size_t offset;
    int flags;
} myst_buf_t;

void myst_buf_release(myst_buf_t* buf);

int myst_buf_clear(myst_buf_t* buf);

int myst_buf_reserve(myst_buf_t* buf, size_t cap);

int myst_buf_resize(myst_buf_t* buf, size_t new_size);

int myst_buf_append(myst_buf_t* buf, const void* p, size_t size);

int myst_buf_insert(myst_buf_t* buf, size_t pos, const void* data, size_t size);

int myst_buf_remove(myst_buf_t* buf, size_t pos, size_t size);

int myst_buf_pack_u64(myst_buf_t* buf, uint64_t x);

int myst_buf_unpack_u64(myst_buf_t* buf, uint64_t* x);

int myst_buf_pack_bytes(myst_buf_t* buf, const void* p, size_t size);

int myst_buf_unpack_bytes(myst_buf_t* buf, const void** p, size_t* size);

int myst_buf_pack_str(myst_buf_t* buf, const char* str);

int myst_buf_unpack_str(myst_buf_t* buf, const char** str, size_t* len);

int myst_buf_pack_strings(myst_buf_t* buf, const char* strings[], size_t count);

int myst_buf_unpack_strings(
    myst_buf_t* buf,
    const char*** strings,
    size_t* count);

#endif /* _MYST_BUF_H */
