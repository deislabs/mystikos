#include <libos/strings.h>

size_t libos_strlcpy(char* dest, const char* src, size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return (size_t)(src - start);
}

size_t libos_strlcat(char* dest, const char* src, size_t size)
{
    size_t n = 0;

    if (size)
    {
        char* end = dest + size - 1;

        while (*dest && dest != end)
        {
            dest++;
            n++;
        }

        while (*src && dest != end)
        {
            n++;
            *dest++ = *src++;
        }

        *dest = '\0';
    }

    while (*src)
    {
        src++;
        n++;
    }

    return n;
}

void* libos_memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = (unsigned char)c;

    return s;
}

void* libos_memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    unsigned char* q = (unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;
}

int libos_memcmp(const void* s1, const void* s2, size_t n)
{
    unsigned char* p = (unsigned char*)s1;
    unsigned char* q = (unsigned char*)s2;

    while (n--)
    {
        if (*p < *q)
            return -1;
        else if (*p > *q)
            return 1;

        p++;
        q++;
    }

    return 0;
}

void* libos_memmove(void* dest_, const void* src_, size_t n)
{
    char* dest = (char*)dest_;
    const char* src = (const char*)src_;

    if (dest != src && n > 0)
    {
        if (dest <= src)
        {
            libos_memcpy(dest, src, n);
        }
        else
        {
            for (src += n, dest += n; n--; dest--, src--)
                dest[-1] = src[-1];
        }
    }

    return dest;
}

size_t libos_strlen(const char* s)
{
    size_t n = 0;

    while (*s++)
        n++;

    return n;
}

int libos_strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

int libos_strncmp(const char* s1, const char* s2, size_t n)
{
    /* Compare first n characters only */
    while (n && (*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
        n--;
    }

    /* If first n characters matched */
    if (n == 0)
        return 0;

    /* Return difference of mismatching characters */
    return *s1 - *s2;
}

size_t libos_strspn(const char* s, const char* accept)
{
    const char* p = s;

    while (*p)
    {
        if (!libos_strchr(accept, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

size_t libos_strcspn(const char* s, const char* reject)
{
    const char* p = s;

    while (*p)
    {
        if (libos_strchr(reject, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

char* libos_strtok_r(char* str, const char* delim, char** saveptr)
{
    char* p = str;
    char* end;

    if (str)
        p = str;
    else if (*saveptr)
        p = *saveptr;
    else
        return NULL;

    /* Find start of next token */
    while (*p && libos_strchr(delim, *p))
        p++;

    /* Find the end of the next token */
    for (end = p; *end && !libos_strchr(delim, *end); end++)
        ;

    if (p == end)
        return NULL;

    if (*end)
    {
        *end++ = '\0';
        *saveptr = end;
    }
    else
        *saveptr = NULL;

    return p;
}

char* libos_strchr(const char* s, int c)
{
    if (s)
    {
        while (*s && *s != c)
            s++;

        if (*s == c)
            return (char*)s;
    }

    return NULL;
}

char* libos_strrchr(const char* s, int c)
{
    if (s)
    {
        char* p = (char*)s + libos_strlen(s);

        if (c == '\0')
            return p;

        while (p != s)
        {
            if (*--p == c)
                return p;
        }
    }

    return NULL;
}
