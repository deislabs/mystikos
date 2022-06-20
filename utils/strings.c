// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <stdio.h>
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
        // To better detect overflow, following calculation has been
        // broken down into smaller pieces
        // alloc_size = ((ntoks + 1) * sizeof(char*)) + nchars;

        // allocate an extra array entry for the null terminator
        // ntoks_plus_one = ntoks + 1
        size_t ntoks_plus_one = 0;
        if (__builtin_uaddl_overflow(ntoks, 1, &ntoks_plus_one))
            ERAISE(-E2BIG);

        // ntoks_mul = (ntoks + 1) * sizeof(char*)
        size_t ntoks_mul = 0;
        if (__builtin_umull_overflow(ntoks_plus_one, sizeof(char*), &ntoks_mul))
            ERAISE(-E2BIG);

        // alloc_size = ((ntoks + 1) * sizeof(char*)) + nchars
        size_t alloc_size = 0;
        if (__builtin_uaddl_overflow(ntoks_mul, nchars, &alloc_size))
            ERAISE(-E2BIG);

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

void* myst_memcchr(const void* b, int c, size_t n)
{
    const uint8_t* p = (uint8_t*)b;

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
        const __uint128_t* p16 = (__uint128_t*)p;
        size_t n16 = n / 16;
        const __uint128_t* end = p16 + n16;
        __uint128_t c16;
        memset(&c16, c, sizeof(c16));

        while (n16 > 0 && *p16 == c16)
        {
            n16--;
            p16++;
        }

        /* calculate the remaining words to be examined */
        size_t r = end - p16;

        p = (uint8_t*)p16;
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

int myst_snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = vsnprintf(str, size, format, ap);
    va_end(ap);

    // check for overflow
    if (ret >= size)
        return -ERANGE;

    return 0;
}

//
// If c is a digit character:
//     then: _digit[c] yields the integer value for that digit character.
//     else: _digit[c] yields 0xFF.
//
// Digit characters fall within these ranges: ['0'-'9'] and ['A'-'Z'].
//
// Examples:
//     _digit['9'] => 9
//     _digit['A'] => 10
//     _digit['Z'] => 35
//     _digit['?'] => 0xFF
//
static const unsigned char _digit[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
};

/* Return true if c is a digit character within the given base */
MYST_INLINE bool _isdigit(char c, int base)
{
    return _digit[(unsigned char)c] < base;
}

unsigned long int myst_strtoul(const char* nptr, char** endptr, int base)
{
    const char* p;
    unsigned long x = 0;
    bool negative = false;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr || base < 0)
        return 0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (myst_isspace(*p))
        p++;

    /* Handle '+' and '-' */
    if (p[0] == '+')
    {
        p++;
    }
    else if (p[0] == '-')
    {
        negative = true;
        p++;
    }

    /* If base is zero, deduce the base from the prefix. */
    if (base == 0)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            base = 16;
        }
        else if (p[0] == '0')
        {
            base = 8;
        }
        else
        {
            base = 10;
        }
    }

    /* Remove any base 16 prefix. */
    if (base == 16)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
        }
    }

    /* Remove any base 8 prefix. */
    if (base == 8)
    {
        if (p[0] == '0')
        {
            p++;
        }
    }

    for (; *p && _isdigit(*p, base); p++)
    {
        /* Multiply by base */
        {
            /* Check for overflow */
            if (x > UINT64_MAX / (unsigned long)base)
            {
                if (endptr)
                    *endptr = (char*)p;

                return UINT64_MAX;
            }

            x = x * (unsigned long)base;
        }

        /* Add digit */
        {
            const unsigned long digit = _digit[(unsigned char)*p];

            /* Check for overflow */
            if (digit > ULONG_MAX - x)
            {
                if (endptr)
                    *endptr = (char*)p;

                return UINT64_MAX;
            }

            x += digit;
        }
    }

    /* Return zero if no digits were found */
    if (p == nptr)
        return 0;

    if (endptr)
        *endptr = (char*)p;

    /* Invert if negative */
    if (negative)
    {
        if (x > LONG_MAX)
        {
            if (x == (unsigned long)LONG_MAX + 1)
                return x;
            else
                return 0;
        }
        x = (unsigned long)-(long)x;
    }

    return x;
}

long int myst_strtol(const char* nptr, char** endptr, int base)
{
    return (long int)strtoul(nptr, endptr, base);
}

double myst_strtod(const char* nptr, char** endptr)
{
    const char* p;
    bool negative = false;
    unsigned long x = 0;
    unsigned long y = 0;
    unsigned long n = 0;
    unsigned long decimal_places = 1;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr)
        return 0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (myst_isspace(*p))
        p++;

    /* Handle '+' and '-' */
    if (p[0] == '+')
    {
        p++;
    }
    else if (p[0] == '-')
    {
        negative = true;
        p++;
    }

    /* Skip any whitespace */
    while (myst_isspace(*p))
        p++;

    /* get x of x.y */
    {
        char* end = NULL;
        x = strtoul(p, &end, 10);
        p = end;

        if (endptr)
            *endptr = (char*)p;
    }

    /* if end of string */
    if (!*p)
        return (double)x;

    if (*p != '.')
    {
        if (endptr)
            *endptr = (char*)p;
        return (double)x;
    }

    p++;

    /* get y of x.y */
    {
        char* end = NULL;
        y = strtoul(p, &end, 10);
        n = end - p;
        p = end;

        if (endptr)
            *endptr = (char*)p;
    }

    /* if no decimal part */
    if (n == 0)
        return (double)x;

    /* calculate the number of decimal places */
    for (size_t i = 0; i < n; i++)
        decimal_places *= 10;

    double result = (double)x + ((double)y / (double)decimal_places);

    if (negative)
        result = -result;

    return result;
}
