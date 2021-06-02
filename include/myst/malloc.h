// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MALLOC_H
#define _MYST_MALLOC_H

#include <stddef.h>
#include <string.h>

#include <myst/defs.h>

void* myst_malloc(size_t size);

void myst_free(void* ptr);

void* myst_calloc(size_t nmemb, size_t size);

void* myst_realloc(void* ptr, size_t size);

int myst_posix_memalign(void** memptr, size_t alignment, size_t size);

void* myst_memalign(size_t alignment, size_t size);

char* myst_strdup(const char* s);

#endif /* _MYST_MALLOC_H */
