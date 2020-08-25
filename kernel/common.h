// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_COMMON_H
#define _LIBOS_COMMON_H

#include <stddef.h>
#include <libos/malloc.h>

__attribute__((deprecated))
void* malloc(size_t size);

__attribute__((deprecated))
void free(void *ptr);

__attribute__((deprecated))
void* calloc(size_t nmemb, size_t size);

__attribute__((deprecated))
void* realloc(void* ptr, size_t size);

#endif /* _LIBOS_COMMON_H */
