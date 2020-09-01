#include <libos/malloc.h>
#include <stdlib.h>

void* __libos_malloc(
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    (void)size;
    (void)file;
    (void)line;
    return malloc(size);
}
