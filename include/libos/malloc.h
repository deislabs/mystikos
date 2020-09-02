#ifndef _LIBOS_MALLOC_H
#define _LIBOS_MALLOC_H

#include <libos/types.h>

void* __libos_malloc(
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void* __libos_calloc(
    size_t nmemb,
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void* __libos_realloc(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void* __libos_memalign(
    size_t alignment,
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void __libos_free(
    void* ptr,
    const char* file,
    size_t line,
    const char* func);

int libos_find_leaks(void);

#define libos_malloc(size) \
    __libos_malloc(size, __FILE__, __LINE__, __FUNCTION__)

#define libos_calloc(nmemb, size) \
    __libos_calloc(nmemb, size, __FILE__, __LINE__, __FUNCTION__)

#define libos_realloc(ptr, size) \
    __libos_realloc(ptr, size, __FILE__, __LINE__, __FUNCTION__)

#define libos_memalign(alignment, size) \
    __libos_memalign(alignment, size, __FILE__, __LINE__, __FUNCTION__)

#define libos_free(ptr) \
    __libos_free(ptr, __FILE__, __LINE__, __FUNCTION__)

#endif /* _LIBOS_MALLOC_H */
