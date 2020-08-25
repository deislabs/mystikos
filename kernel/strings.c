#include <libos/strings.h>
#include <libos/eraise.h>
#include <libos/tcall.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "common.h"

int libos_strsplit(
    const char* str,
    const char* delim,
    char*** toks_out,
    size_t* ntoks_out)
{
    int ret = 0;
    size_t alloc_size;
    char** toks = NULL;
    size_t ntoks = 0;
    size_t nchars = 0;

    if (toks_out)
        *toks_out = NULL;

    if (ntoks_out)
        *ntoks_out = 0;

    if (!str || !delim || !toks_out)
        ERAISE(-EINVAL);

    /* First pass: determine memory requirements */
    {
    	const char* p = str;

        while (*p)
        {
            size_t r;

            /* skip over the delimiter characters */
            r = strspn(p, delim);
            p += r;

            /* skip over the token */
            if ((r = strcspn(p, delim)))
                ntoks++;

            /* include the null byte in the character count */
            nchars += r + 1;
            p += r;
        }
    }

    /* Allocate the array of pointers followed by the strings */
    {
        /* allocate an extra array entry for the null terminator */
        alloc_size = ((ntoks + 1)* sizeof(char*)) + nchars;

        if (!(toks = libos_malloc(alloc_size)))
            ERAISE(-ENOMEM);
    }

    /* Second pass: copy the strings into place */
    {
    	const char* in = str;
    	char* out = (char*)&toks[ntoks + 1];
        size_t index = 0;

        while (*in)
        {
            size_t r;

            /* skip over the delimiter characters */
            r = strspn(in, delim);
            in += r;

            /* skip over the token */
            if ((r = strcspn(in, delim)))
            {
                toks[index++] = out;
                strncpy(out, in, r);
                out[r] = '\0';
                out += r + 1;
            }

            in += r;
        }

        /* null terminate the array */
        toks[index] = NULL;
    }

    *toks_out = toks;
    toks = NULL;
    *ntoks_out = ntoks;

done:

    if (toks)
        libos_free(toks);

    return ret;
}

int libos_strjoin(
    const char* toks[],
    size_t ntoks,
    const char* ldelim,
    const char* delim,
    const char* rdelim,
    char** str_out)
{
    int ret = 0;
    size_t n = 0;
    char* str = NULL;
    char* p;

    if ((!toks && ntoks) || !str_out)
        ERAISE(-EINVAL);

    /* Calculate the space needed for the new string */
    {
        /* Space for left delimiter */
        if (ldelim)
            n += libos_strlen(ldelim);

        /* Space for right delimiter */
        if (rdelim)
            n += libos_strlen(rdelim);

        /* Space for the strings and internal delimiters */
        for (size_t i = 0; i < ntoks; i++)
        {
            n += libos_strlen(toks[i]);

            /* Space for internal delimiters */
            if (delim && (i + 1) != ntoks)
                n += libos_strlen(delim);
        }

        /* Space for null terminator */
        n++;
    }

    /* Allocate space */
    if (!(str = libos_malloc(n)))
        ERAISE(-ENOMEM);

    /* Copy the tokens and delimiters onto the string */
    {
        p = str;

        /* Copy the left delimiter */
        if (ldelim)
        {
            n = libos_strlen(ldelim);
            libos_memcpy(p, ldelim, n);
            p += n;
        }

        /* Copy the strings and internal delimiters */
        for (size_t i = 0; i < ntoks; i++)
        {
            /* Copy the token */
            n = libos_strlen(toks[i]);
            libos_memcpy(p, toks[i], n);
            p += n;

            /* Space for internal delimiters */
            if (delim && (i + 1) != ntoks)
            {
                n = libos_strlen(delim);
                libos_memcpy(p, delim, n);
                p += n;
            }
        }

        /* Copy the right delimiter */
        if (rdelim)
        {
            n = libos_strlen(rdelim);
            libos_memcpy(p, rdelim, n);
            p += n;
        }

        /* Null terminate the string */
        *p = '\0';
    }

    *str_out = str;
    str = NULL;

done:

    if (str)
        libos_free(str);

    return ret;
}

ssize_t libos_memremove(void* data, size_t size, size_t pos, size_t count)
{
    ssize_t ret = 0;
    size_t rem;

    if (!data || pos > size || pos + count > size)
        ERAISE(-ERANGE);

    rem = size - pos;

    if (rem)
        libos_memmove((uint8_t*)data + pos, (uint8_t*)data + pos + count, rem);

    ret = (ssize_t)(size - count);

done:
    return ret;
}

ssize_t libos_memremove_u64(void* data, size_t size, size_t pos, size_t count)
{
    ssize_t ret = 0;
    size_t tsize = size * sizeof(uint64_t);
    size_t tpos = pos * sizeof(uint64_t);
    size_t tcount = count * sizeof(uint64_t);
    ssize_t n;

    ECHECK((n = libos_memremove(data, tsize, tpos, tcount)));

    ret = n / (ssize_t)sizeof(uint64_t);

done:
    return ret;
}

size_t libos_tokslen(const char* toks[])
{
    size_t n = 0;

    if (!toks)
        return 0;

    for (size_t i = 0; toks[i]; i++)
        n++;

    return n;
}

void libos_toks_dump(const char* toks[])
{
    printf("=== libos_toks_dump()\n");

    for (size_t i = 0; toks[i]; i++)
        printf("%s\n", toks[i]);

    printf("\n");
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

int libos_vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return (int)libos_tcall_vsnprintf(str, size, format, ap);
}

int libos_snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = libos_vsnprintf(str, size, format, ap);
    va_end(ap);

    return ret;
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

char* libos_strdup(const char* s)
{
    char* p;
    size_t len;

    if (!s)
        return NULL;

    len = libos_strlen(s);

    if (!(p = libos_malloc(len + 1)))
        return NULL;

    libos_memcpy(p, s, len + 1);

    return p;
}
