#include <string.h>

#include <libos/strings.h>

void* libos_memset(void* s, int c, size_t n)
{
    return memset(s, c, n);
}

void* libos_memcpy(void* dest, const void* src, size_t n)
{
    return memcpy(dest, src, n);
}

int libos_memcmp(const void* s1, const void* s2, size_t n)
{
    return memcmp(s1, s2, n);
}

void* libos_memmove(void* dest, const void* src, size_t n)
{
    return memmove(dest, src, n);
}

size_t libos_strlen(const char* s)
{
    return strlen(s);
}

int libos_strcmp(const char* s1, const char* s2)
{
    return strcmp(s1, s2);
}

int libos_strncmp(const char* s1, const char* s2, size_t n)
{
    return strncmp(s1, s2, n);
}

size_t libos_strspn(const char* s, const char* accept)
{
    return strspn(s, accept);
}

size_t libos_strcspn(const char* s, const char* reject)
{
    return strcspn(s, reject);
}

char* libos_strtok_r(char* str, const char* delim, char** saveptr)
{
    return strtok_r(str, delim, saveptr);
}

char* libos_strchr(const char* s, int c)
{
    return strchr(s, c);
}

char* libos_strrchr(const char* s, int c)
{
    return strrchr(s, c);
}
