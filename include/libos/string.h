#ifndef _LIBOS_STRING_H
#define _LIBOS_STRING_H

#include <libos/defs.h>
#include <stddef.h>

#define STRING_DYNAMIC 1

typedef struct string
{
    int flags;
    char* ptr;
    size_t len;
    size_t cap;
} string_t;

#define STRING_BUF(BUF)            \
    {                              \
        0, BUF, 0, sizeof(BUF) - 1 \
    }

LIBOS_INLINE void string_init(string_t* string, char* buf, size_t size)
{
    string->flags = 0;
    string->ptr = buf;
    string->len = 0;
    string->cap = size - 1;
}

LIBOS_INLINE const char* string_ptr(const string_t* string)
{
    return string->ptr;
}

LIBOS_INLINE size_t string_len(const string_t* string)
{
    return string->len;
}

LIBOS_INLINE size_t string_cap(const string_t* string)
{
    return string->cap;
}

int string_cat(string_t* string, const char* s);

int string_cpy(string_t* string, const char* s);

#endif /* _LIBOS_STRING_H */
