// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OEL_BUF64_h
#define _OEL_BUF64_h

#include <stddef.h>
#include <stdint.h>

#define BUFU64_INITIALIZER { NULL, 0, 0 }

typedef struct _bufu64
{
    uint64_t* data;
    size_t size;
    size_t cap;
} oel_bufu64_t;

void oel_bufu64_release(oel_bufu64_t* buf);

void oel_bufu64_clear(oel_bufu64_t* buf);

int oel_bufu64_resize(oel_bufu64_t* buf, size_t new_size);

int oel_bufu64_append(oel_bufu64_t* buf, const uint64_t* data, size_t size);

#endif /* _OEL_BUF64_h */
