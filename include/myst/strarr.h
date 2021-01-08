// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_STRARR_H
#define _MYST_STRARR_H

#include <myst/types.h>

// clang-format off
#define MYST_STRARR_INITIALIZER { NULL, 0, 0 }
// clang-format on

typedef struct myst_strarr
{
    char** data;
    size_t size;
    size_t capacity;
} myst_strarr_t;

void myst_strarr_release(myst_strarr_t* self);

int myst_strarr_append(myst_strarr_t* self, const char* data);

int myst_strarr_remove(myst_strarr_t* self, size_t index);

void myst_strarr_sort(myst_strarr_t* self);

#endif /* _MYST_STRARR_H */
