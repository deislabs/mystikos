#include <stdio.h>

extern size_t __fread_chk(
    void* ptr,
    size_t ptrlen,
    size_t size,
    size_t n,
    FILE* stream)
{
    return fread(ptr, size, n, stream);
}
