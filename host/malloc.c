#include <libos/malloc.h>
#include <libos/defs.h>
#include <stdlib.h>
#include <malloc.h>

void libos_free(void* ptr)
{
    return free(ptr);
}

void* libos_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void* libos_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

void* libos_memalign(size_t alignment, size_t size)
{
    return memalign(alignment, size);
}
