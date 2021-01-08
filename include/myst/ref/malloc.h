// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MALLOC_H
#define _MYST_MALLOC_H

#include <myst/types.h>

void* __myst_malloc(
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void* __myst_calloc(
    size_t nmemb,
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void* __myst_realloc(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void* __myst_memalign(
    size_t alignment,
    size_t size,
    const char* file,
    size_t line,
    const char* func);

void __myst_free(void* ptr, const char* file, size_t line, const char* func);

int myst_find_leaks(void);

typedef struct myst_malloc_stats
{
    size_t usage;      /* bytes currently in use */
    size_t peak_usage; /* the maximum bytes ever in use */
} myst_malloc_stats_t;

/* only works with MYST_ENABLE_LEAK_CHECKER flags. Returns -ENOTSUP */
int myst_get_malloc_stats(myst_malloc_stats_t* stats);

#define myst_malloc(size) \
    __myst_malloc(size, __FILE__, __LINE__, __FUNCTION__)

#define myst_calloc(nmemb, size) \
    __myst_calloc(nmemb, size, __FILE__, __LINE__, __FUNCTION__)

#define myst_realloc(ptr, size) \
    __myst_realloc(ptr, size, __FILE__, __LINE__, __FUNCTION__)

#define myst_memalign(alignment, size) \
    __myst_memalign(alignment, size, __FILE__, __LINE__, __FUNCTION__)

#define myst_free(ptr) __myst_free(ptr, __FILE__, __LINE__, __FUNCTION__)

#endif /* _MYST_MALLOC_H */
