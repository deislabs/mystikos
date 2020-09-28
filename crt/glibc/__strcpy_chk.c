#include <stddef.h>
#include <string.h>

char* __strcpy_chk(char* dest, const char* src, size_t destlen)
{
    return strcpy(dest, src);
}
