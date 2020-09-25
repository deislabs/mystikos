#include <libos/string.h>

int string_cpy(string_t* string, const char* s)
{
    size_t n = string->cap;
    char* p = string->ptr;

    string->len = 0;

    while (*s && n)
    {
        *p++ = *s++;
        n--;
    }

    if (*s)
    {
        string->ptr[string->len] = '\0';
        return -1;
    }

    *p = '\0';
    string->len = (size_t)(p - string->ptr);

    return 0;
}

int string_cat(string_t* string, const char* s)
{
    size_t n = string->cap - string->len;
    char* p = string->ptr + string->len;

    while (*s && n--)
        *p++ = *s++;

    if (*s)
    {
        string->ptr[string->len] = '\0';
        return -1;
    }

    *p = '\0';
    string->len = (size_t)(p - string->ptr);

    return 0;
}
