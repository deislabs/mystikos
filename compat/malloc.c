#include <malloc.h>
#include <stdlib.h>

#include <libos/malloc.h>

void* __libos_malloc(
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    (void)file;
    (void)line;
    (void)func;
    return malloc(size);
}

void* __libos_calloc(
    size_t nmemb,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    (void)file;
    (void)line;
    (void)func;
    return calloc(nmemb, size);
}

void __libos_free(void* ptr, const char* file, size_t line, const char* func)
{
    (void)file;
    (void)line;
    (void)func;
    free(ptr);
}

void* __libos_realloc(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    (void)file;
    (void)line;
    (void)func;
    return realloc(ptr, size);
}

void* __libos_memalign(
    size_t alignment,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    (void)file;
    (void)line;
    (void)func;
    return memalign(alignment, size);
}
