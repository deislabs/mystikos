#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <myst/defs.h>
#include <myst/debugmalloc.h>
#include <myst/malloc.h>

// musl libc memory allocation functions
void* libc_malloc(size_t size);
void libc_free(void* ptr);
void* libc_calloc(size_t nmemb, size_t size);
void* libc_realloc(void* ptr, size_t size);
void* libc_memalign(size_t alignment, size_t size);
int libc_posix_memalign(void **memptr, size_t alignment, size_t size);
size_t libc_malloc_usable_size(void* ptr);

// override "myst_" functions with "libc_ functions:
#define myst_malloc libc_malloc
#define myst_free libc_free
#define myst_realloc libc_realloc
#define myst_calloc libc_calloc
#define myst_memalign libc_memalign
#define myst_posix_memalign libc_posix_memalign
#include "../kernel/debugmalloc.c"

bool __crt_crt_memcheck;

/*
**==============================================================================
**
** define strong versions of the standard memory allocator functions to
** override the weak versions defined in musl libc.
**
**==============================================================================
*/

void* malloc(size_t size)
{
    if (__crt_crt_memcheck)
    {
        return myst_debug_malloc(size);
    }
    else
    {
        return libc_malloc(size);
    }
}

void free(void* ptr)
{
    if (__crt_crt_memcheck)
    {
        return myst_debug_free(ptr);
    }
    else
    {
        return libc_free(ptr);
    }
}

void* calloc(size_t nmemb, size_t size)
{
    if (__crt_crt_memcheck)
    {
        return myst_debug_calloc(nmemb, size);
    }
    else
    {
        return libc_calloc(nmemb, size);
    }
}

void* realloc(void* ptr, size_t size)
{
    if (__crt_crt_memcheck)
    {
        return myst_debug_realloc(ptr, size);
    }
    else
    {
        return libc_realloc(ptr, size);
    }
}

void* memalign(size_t alignment, size_t size)
{
    if (__crt_crt_memcheck)
    {
        return myst_debug_memalign(alignment, size);
    }
    else
    {
        return libc_memalign(alignment, size);
    }
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if (__crt_crt_memcheck)
    {
        return myst_debug_posix_memalign(memptr, alignment, size);
    }
    else
    {
        return libc_posix_memalign(memptr, alignment, size);
    }
}

size_t malloc_usable_size(void* ptr)
{
    if (__crt_crt_memcheck)
    {
        return myst_debug_malloc_usable_size(ptr);
    }
    else
    {
        return libc_malloc_usable_size(ptr);
    }
}
