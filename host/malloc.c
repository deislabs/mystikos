#include <libos/defs.h>
#include <libos/malloc.h>
#include <malloc.h>
#include <stdlib.h>

void __libos_free(void* ptr, const char* file, size_t line, const char* func)
{
    return free(ptr);
}

void* __libos_calloc(
    size_t nmemb,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    return calloc(nmemb, size);
}

void* __libos_realloc(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    return realloc(ptr, size);
}

void* __libos_memalign(
    size_t alignment,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    return memalign(alignment, size);
}
