// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BUFU64_H
#define _MYST_BUFU64_H

#include <stddef.h>
#include <stdint.h>

// clang-format off
#define BUFU64_INITIALIZER { NULL, 0, 0 }
// clang-format on

typedef struct myst_bufu64
{
    uint64_t* data;
    size_t size;
    size_t cap;
} myst_bufu64_t;

int myst_bufu64_init(myst_bufu64_t* buf, uint64_t* data, size_t size);

void myst_bufu64_release(myst_bufu64_t* buf);

void myst_bufu64_clear(myst_bufu64_t* buf);

int myst_bufu64_reserve(myst_bufu64_t* buf, size_t cap);

int myst_bufu64_resize(myst_bufu64_t* buf, size_t new_size);

int myst_bufu64_append(myst_bufu64_t* buf, const uint64_t* data, size_t size);

int myst_bufu64_append1(myst_bufu64_t* buf, uint64_t data);

int myst_bufu64_insert(
    myst_bufu64_t* buf,
    size_t pos,
    const uint64_t* data,
    size_t size);

int myst_bufu64_remove(myst_bufu64_t* buf, size_t pos, size_t size);

#endif /* _MYST_BUFU64_H */
