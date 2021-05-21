// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <myst/crash.h>
#include <myst/eraise.h>
#include <myst/strings.h>
#include <myst/tcall.h>

#define USE_BUILTIN_MEMSET
#define USE_BUILTIN_MEMCPY
#define USE_LOOP_UNROLLING

int myst_strsplit(
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
        alloc_size = ((ntoks + 1) * sizeof(char*)) + nchars;

        if (!(toks = malloc(alloc_size)))
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
        free(toks);

    return ret;
}

int myst_strjoin(
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
            n += strlen(ldelim);

        /* Space for right delimiter */
        if (rdelim)
            n += strlen(rdelim);

        /* Space for the strings and internal delimiters */
        for (size_t i = 0; i < ntoks; i++)
        {
            n += strlen(toks[i]);

            /* Space for internal delimiters */
            if (delim && (i + 1) != ntoks)
                n += strlen(delim);
        }

        /* Space for null terminator */
        n++;
    }

    /* Allocate space */
    if (!(str = malloc(n)))
        ERAISE(-ENOMEM);

    /* Copy the tokens and delimiters onto the string */
    {
        p = str;

        /* Copy the left delimiter */
        if (ldelim)
        {
            n = strlen(ldelim);
            memcpy(p, ldelim, n);
            p += n;
        }

        /* Copy the strings and internal delimiters */
        for (size_t i = 0; i < ntoks; i++)
        {
            /* Copy the token */
            n = strlen(toks[i]);
            memcpy(p, toks[i], n);
            p += n;

            /* Space for internal delimiters */
            if (delim && (i + 1) != ntoks)
            {
                n = strlen(delim);
                memcpy(p, delim, n);
                p += n;
            }
        }

        /* Copy the right delimiter */
        if (rdelim)
        {
            n = strlen(rdelim);
            memcpy(p, rdelim, n);
            p += n;
        }

        /* Null terminate the string */
        *p = '\0';
    }

    *str_out = str;
    str = NULL;

done:

    if (str)
        free(str);

    return ret;
}

ssize_t myst_memremove(void* data, size_t size, size_t pos, size_t count)
{
    ssize_t ret = 0;
    size_t rem;

    if (!data || pos > size || pos + count > size)
        ERAISE(-ERANGE);

    rem = size - pos;

    if (rem)
        memmove((uint8_t*)data + pos, (uint8_t*)data + pos + count, rem);

    ret = (ssize_t)(size - count);

done:
    return ret;
}

ssize_t myst_memremove_u64(void* data, size_t size, size_t pos, size_t count)
{
    ssize_t ret = 0;
    size_t tsize = size * sizeof(uint64_t);
    size_t tpos = pos * sizeof(uint64_t);
    size_t tcount = count * sizeof(uint64_t);
    ssize_t n;

    ECHECK((n = myst_memremove(data, tsize, tpos, tcount)));

    ret = n / (ssize_t)sizeof(uint64_t);

done:
    return ret;
}

size_t myst_tokslen(const char* toks[])
{
    size_t n = 0;

    if (!toks)
        return 0;

    for (size_t i = 0; toks[i]; i++)
        n++;

    return n;
}

void myst_toks_dump(const char* toks[])
{
    printf("=== myst_toks_dump()\n");

    for (size_t i = 0; toks[i]; i++)
        printf("%s\n", toks[i]);

    printf("\n");
}

size_t myst_strlcpy(char* dest, const char* src, size_t size)
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

size_t myst_strlcat(char* dest, const char* src, size_t size)
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

bool myst_isspace(char c)
{
    switch (c)
    {
        case ' ':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
        case '\v':
            return true;
        default:
            return false;
    }
}

#pragma GCC push_options
#pragma GCC optimize "-O3"
void* myst_memcchr(const void* s, int c, size_t n)
{
    const uint8_t* p = (uint8_t*)s;

    /* while more bytes and pointer is not 16-byte aligned */
    while (n && (((ptrdiff_t)p) & 0x000000000000000f))
    {
        if (*p != c)
            return (void*)p;
        n--;
        p++;
    }

    /* if more than 16 bytes and p is 16-byte aligned */
    if (n > 16 && ((ptrdiff_t)p & 0x000000000000000f) == 0)
    {
        const __uint128_t* pp = (__uint128_t*)p;
        size_t nn = n / 16;
        const __uint128_t* end = pp + nn;
        __uint128_t cc;
        memset(&cc, c, sizeof(cc));

        while (nn > 0 && *pp == cc)
        {
            nn--;
            pp++;
        }

        /* calculate the remaining words to be examined */
        size_t r = end - pp;

        p = (uint8_t*)pp;
        n = (r * 16) + (n % 16);
    }

    while (n > 0)
    {
        if (*p != c)
            return (void*)p;
        p++;
        n--;
    }

    return NULL;
}
#pragma GCC pop_options

#pragma GCC push_options
#pragma GCC optimize "-O3"
void* myst_memchr(const void* s, int c, size_t n)
{
    const uint8_t* p = (uint8_t*)s;

    while (n > 0)
    {
        if (*p == c)
            return (void*)p;
        p++;
        n--;
    }

    return NULL;
}
#pragma GCC pop_options

#pragma GCC push_options
#pragma GCC optimize "-O3"
uint32_t* myst_memset_u32(uint32_t* s, uint32_t c, size_t n)
{
    uint32_t* p = s;

    /* unroll loop to factor of 8 */
    while (n >= 8)
    {
        p[0] = c;
        p[1] = c;
        p[2] = c;
        p[3] = c;
        p[4] = c;
        p[5] = c;
        p[6] = c;
        p[7] = c;
        p += 8;
        n -= 8;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough="
    switch (n)
    {
        case 7:
            *p++ = c;
        case 6:
            *p++ = c;
        case 5:
            *p++ = c;
        case 4:
            *p++ = c;
        case 3:
            *p++ = c;
        case 2:
            *p++ = c;
        case 1:
            *p++ = c;
    }
#pragma GCC diagnostic pop

    return s;
}
#pragma GCC pop_options

__attribute__((__always_inline__)) static __inline__ void _bzero_u128_16_inline(
    __uint128_t* p)
{
    p[0] = 0;
    p[1] = 0;
    p[2] = 0;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0;
    p[6] = 0;
    p[7] = 0;
    p[8] = 0;
    p[9] = 0;
    p[10] = 0;
    p[11] = 0;
    p[12] = 0;
    p[13] = 0;
    p[14] = 0;
    p[15] = 0;
}

#pragma GCC push_options
#pragma GCC optimize "-O3"
__uint128_t* myst_bzero_u128(__uint128_t* s, size_t n)
{
    __uint128_t* p = s;

    while (n >= 64)
    {
        _bzero_u128_16_inline(&p[0]);
        _bzero_u128_16_inline(&p[16]);
        _bzero_u128_16_inline(&p[32]);
        _bzero_u128_16_inline(&p[48]);
        p += 64;
        n -= 64;
    }

    /* handle remaining bytes if any */
    while (n--)
        *p++ = 0;

    return s;
}
#pragma GCC pop_options
