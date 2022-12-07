// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_DEBUGMALLOC_H
#define _MYST_DEBUGMALLOC_H

#include <stdbool.h>
#include <stddef.h>

void* myst_debug_malloc(size_t size);

void myst_debug_free(void* ptr);

void* myst_debug_calloc(size_t nmemb, size_t size);

void* myst_debug_realloc(void* ptr, size_t size);

int myst_debug_posix_memalign(void** memptr, size_t alignment, size_t size);

void* myst_debug_memalign(size_t alignment, size_t size);

size_t myst_debug_malloc_check(void);

size_t myst_debug_malloc_usable_size(void* ptr);

/* check integrity of all allocated blocks */
size_t myst_memcheck(void);

#endif /* _MYST_DEBUGMALLOC_H */
