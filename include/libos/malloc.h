#ifndef _LIBOS_MALLOC_H
#define _LIBOS_MALLOC_H

#include <libos/types.h>

void* libos_malloc(size_t size);

void libos_free(void* ptr);

void* libos_calloc(size_t nmemb, size_t size);

void* libos_realloc(void* ptr, size_t size);

void* libos_memalign(size_t alignment, size_t size);

#endif /* _LIBOS_MALLOC_H */
