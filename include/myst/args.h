// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ARGS_H
#define _MYST_ARGS_H

#include <myst/defs.h>
#include <stddef.h>
#include <stdint.h>

typedef struct myst_args
{
    const char** data;
    size_t size;
    size_t cap;
} myst_args_t;

int myst_args_init(myst_args_t* self);

/* data must be null terminated (not included in the size) */
int myst_args_adopt(myst_args_t* self, const char** data, size_t size);

void myst_args_release(myst_args_t* self);

int myst_args_reserve(myst_args_t* self, size_t cap);

int myst_args_append(myst_args_t* self, const char** data, size_t size);

int myst_args_append1(myst_args_t* self, const char* data);

int myst_args_prepend(myst_args_t* self, const char** data, size_t size);

int myst_args_prepend1(myst_args_t* self, const char* data);

int myst_args_insert(
    myst_args_t* self,
    size_t pos,
    const char** data,
    size_t size);

int myst_args_remove(myst_args_t* self, size_t pos, size_t size);

int myst_args_pack(
    const myst_args_t* self,
    void** packed_data,
    size_t* packed_size);

int myst_args_unpack(
    myst_args_t* self,
    const void* packed_data,
    size_t packed_size);

void myst_args_dump(myst_args_t* self);

/* looks at the first n chars and returns pos if found, else returns -ENOENT */
int myst_args_find(myst_args_t* self, const char* data, size_t n);

#endif /* _MYST_ARGS_H */
