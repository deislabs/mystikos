// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_STRARR_H
#define _LIBOS_STRARR_H

#include <libos/types.h>

#define LIBOS_STRARR_INITIALIZER { NULL, 0, 0 }

typedef struct libos_strarr
{
    char** data;
    size_t size;
    size_t capacity;
} libos_strarr_t;

void libos_strarr_release(libos_strarr_t* self);

int libos_strarr_append(libos_strarr_t* self, const char* data);

int libos_strarr_remove(libos_strarr_t* self, size_t index);

void libos_strarr_sort(libos_strarr_t* self);

#endif /* _LIBOS_STRARR_H */
