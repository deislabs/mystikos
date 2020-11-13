// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_BUFU64_H
#define _LIBOS_BUFU64_H

#include <stddef.h>
#include <stdint.h>

// clang-format off
#define BUFU64_INITIALIZER { NULL, 0, 0 }
// clang-format on

typedef struct libos_bufu64
{
    uint64_t* data;
    size_t size;
    size_t cap;
} libos_bufu64_t;

int libos_bufu64_init(libos_bufu64_t* buf, uint64_t* data, size_t size);

void libos_bufu64_release(libos_bufu64_t* buf);

void libos_bufu64_clear(libos_bufu64_t* buf);

int libos_bufu64_reserve(libos_bufu64_t* buf, size_t cap);

int libos_bufu64_resize(libos_bufu64_t* buf, size_t new_size);

int libos_bufu64_append(libos_bufu64_t* buf, const uint64_t* data, size_t size);

int libos_bufu64_append1(libos_bufu64_t* buf, uint64_t data);

int libos_bufu64_insert(
    libos_bufu64_t* buf,
    size_t pos,
    const uint64_t* data,
    size_t size);

int libos_bufu64_remove(libos_bufu64_t* buf, size_t pos, size_t size);

#endif /* _LIBOS_BUFU64_H */
