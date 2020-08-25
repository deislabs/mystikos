#include <libos/malloc.h>
#include <libos/tcall.h>
#include <libos/crash.h>
#include <libos/deprecated.h>

long libos_tcall_allocate(
    void* ptr,
    size_t alignment,
    size_t size,
    int clear,
    void** new_ptr)
{
    long params[6];
    params[0] = (long)ptr;
    params[1] = (long)alignment;
    params[2] = (long)size;
    params[3] = (long)clear;
    params[4] = (long)new_ptr;

    return libos_tcall(LIBOS_TCALL_ALLOCATE, params);
}

long libos_tcall_deallocate(void* ptr)
{
    long params[6];
    params[0] = (long)ptr;

    return libos_tcall(LIBOS_TCALL_DEALLOCATE, params);
}

void* libos_malloc(size_t size)
{
    void* p = NULL;

    if (libos_tcall_allocate(NULL, 0, size, 0, &p) != 0 || !p)
        return NULL;

    return p;
}

void libos_free(void* ptr)
{
    if (libos_tcall_deallocate(ptr) != 0)
        libos_crash();
}

void* libos_calloc(size_t nmemb, size_t size)
{
    void* p = NULL;
    size_t n = nmemb * size;

    if (libos_tcall_allocate(NULL, 0, n, 1, &p) != 0 || !p)
        return NULL;

    return p;
}

void* libos_realloc(void* ptr, size_t size)
{
    void* p = NULL;

    if (libos_tcall_allocate(ptr, 0, size, 0, &p) != 0 || !p)
        return NULL;

    return p;
}

void* libos_memalign(size_t alignment, size_t size)
{
    void* p = NULL;

    if (libos_tcall_allocate(NULL, alignment, size, 0, &p) != 0 || !p)
        return NULL;

    return p;
}
