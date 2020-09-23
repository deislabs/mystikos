// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_ARGS_H
#define _LIBOS_ARGS_H

#include <libos/defs.h>
#include <stddef.h>
#include <stdint.h>

typedef struct libos_args
{
    const char** data;
    size_t size;
    size_t cap;
} libos_args_t;

int libos_args_init(libos_args_t* self);

/* data must be null terminated (not included in the size) */
int libos_args_adopt(libos_args_t* self, const char** data, size_t size);

void libos_args_release(libos_args_t* self);

int libos_args_reserve(libos_args_t* self, size_t cap);

int libos_args_append(libos_args_t* self, const char** data, size_t size);

int libos_args_append1(libos_args_t* self, const char* data);

int libos_args_prepend(libos_args_t* self, const char** data, size_t size);

int libos_args_prepend1(libos_args_t* self, const char* data);

int libos_args_insert(
    libos_args_t* self,
    size_t pos,
    const char** data,
    size_t size);

int libos_args_remove(libos_args_t* self, size_t pos, size_t size);

int libos_args_pack(
    const libos_args_t* self,
    void** packed_data,
    size_t* packed_size);

int libos_args_unpack(
    libos_args_t* self,
    const void* packed_data,
    size_t packed_size);

#endif /* _LIBOS_ARGS_H */
