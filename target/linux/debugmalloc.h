// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_DEBUG_MALLOC_H
#define _LIBOS_DEBUG_MALLOC_H

#include <libos/types.h>

void* libos_debug_malloc(size_t size);

void libos_debug_free(void* ptr);

void* libos_debug_calloc(size_t nmemb, size_t size);

void* libos_debug_realloc(void* ptr, size_t size);

void* libos_debug_memalign(size_t alignment, size_t size);

int libos_debug_posix_memalign(void** memptr, size_t alignment, size_t size);

size_t libos_debug_malloc_usable_size(void* ptr);

#endif /* _LIBOS_DEBUG_MALLOC_H */
