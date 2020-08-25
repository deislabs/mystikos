// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_BUF64_H
#define _LIBOS_BUF64_H

#include <stddef.h>
#include <stdint.h>

#define BUFU64_INITIALIZER { NULL, 0, 0 }

typedef struct libos_bufu64
{
    uint64_t* data;
    size_t size;
    size_t cap;
} libos_bufu64_t;

void libos_bufu64_release(libos_bufu64_t* buf);

void libos_bufu64_clear(libos_bufu64_t* buf);

int libos_bufu64_resize(libos_bufu64_t* buf, size_t new_size);

int libos_bufu64_append(libos_bufu64_t* buf, const uint64_t* data, size_t size);

int libos_bufu64_append1(libos_bufu64_t* buf, uint64_t data);

#endif /* _LIBOS_BUF64_H */
