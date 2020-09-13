#include <stdlib.h>
#include <string.h>

#include <libos/crash.h>
#include <libos/eraise.h>
#include <libos/malloc.h>
#include <libos/strings.h>
#include <libos/tcall.h>

#define USE_BUILTIN_MEMSET
#define USE_BUILTIN_MEMCPY
#define USE_LOOP_UNROLLING

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
            r = libos_strspn(p, delim);
            p += r;

            /* skip over the token */
            if ((r = libos_strcspn(p, delim)))
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
            r = libos_strspn(in, delim);
            in += r;

            /* skip over the token */
            if ((r = libos_strcspn(in, delim)))
            {
                toks[index++] = out;
                libos_strncpy(out, in, r);
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
    libos_console_printf(STDOUT_FILENO, "=== libos_toks_dump()\n");

    for (size_t i = 0; toks[i]; i++)
        libos_console_printf(STDOUT_FILENO, "%s\n", toks[i]);

    libos_console_printf(STDOUT_FILENO, "\n");
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

int libos_console_printf(int fd, const char* format, ...)
{
    char buf[1024];
    va_list ap;
    int count;

    va_start(ap, format);
    count = libos_vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    if (count < 0 || (size_t)count >= sizeof(buf))
        return -EINVAL;

    return (int)libos_tcall_write_console(fd, buf, (size_t)count);
}

int libos_console_vprintf(int fd, const char* format, va_list ap)
{
    char buf[1024];
    int count;

    count = libos_vsnprintf(buf, sizeof(buf), format, ap);

    if (count < 0 || (size_t)count >= sizeof(buf))
        return -EINVAL;

    return (int)libos_tcall_write_console(fd, buf, (size_t)count);
}

char* libos_strncpy(char* dest, const char* src, size_t n)
{
    size_t i;

    for (i = 0; i < n && src[i]; i++)
        dest[i] = src[i];

    for (; i < n; i++)
        dest[i] = '\0';

    return dest;
}

int libos_veprintf(const char* format, va_list ap)
{
    return libos_console_vprintf(STDERR_FILENO, format, ap);
}

int libos_vprintf(const char* format, va_list ap)
{
    return libos_console_vprintf(STDOUT_FILENO, format, ap);
}

int libos_eprintf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = libos_console_vprintf(STDERR_FILENO, format, ap);
    va_end(ap);

    return n;
}

int libos_printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = libos_console_vprintf(STDOUT_FILENO, format, ap);
    va_end(ap);

    return n;
}

void __libos_panic(
    const char* file,
    size_t line,
    const char* func,
    const char* format,
    ...)
{
    va_list ap;

    libos_console_printf(
        STDERR_FILENO, "kernel panic: %s(%zu): %s(): ", file, line, func);

    va_start(ap, format);
    libos_console_vprintf(STDERR_FILENO, format, ap);
    va_end(ap);

    libos_console_printf(STDERR_FILENO, "\n");

    libos_crash();
}

void* libos_memset(void* s, int c, size_t n)
{
#ifdef USE_BUILTIN_MEMSET

    unsigned char* p = (unsigned char*)s;

    while (n >= 1024)
    {
        __builtin_memset(p, c, 1024);
        n -= 1024;
        p += 1024;
    }

    while (n >= 256)
    {
        __builtin_memset(p, c, 256);
        n -= 256;
        p += 256;
    }

    while (n >= 64)
    {
        __builtin_memset(p, c, 64);
        n -= 64;
        p += 64;
    }

    while (n >= 16)
    {
        __builtin_memset(p, c, 16);
        n -= 16;
        p += 16;
    }

    while (n--)
        *p++ = (uint8_t)c;

    return s;

#else /* USE_BUILTIN_MEMSET */

    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = (unsigned char)c;

    return s;

#endif /* !USE_BUILTIN_MEMSET */
}

void* libos_memcpy(void* dest, const void* src, size_t n)
{
#ifdef USE_BUILTIN_MEMCPY

    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

    while (n >= 1024)
    {
        __builtin_memcpy(p, q, 1024);
        n -= 1024;
        p += 1024;
        q += 1024;
    }

    while (n >= 256)
    {
        __builtin_memcpy(p, q, 256);
        n -= 256;
        p += 256;
        q += 256;
    }

    while (n >= 64)
    {
        __builtin_memcpy(p, q, 64);
        n -= 64;
        p += 64;
        q += 64;
    }

    while (n >= 16)
    {
        __builtin_memcpy(p, q, 16);
        n -= 16;
        p += 16;
        q += 16;
    }

    while (n--)
        *p++ = *q++;

    return dest;

#else /* USE_BUILTIN_MEMCPY */

    unsigned char* p = (unsigned char*)dest;
    unsigned char* q = (unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;

#endif /* !USE_BUILTIN_MEMCPY */
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
#ifdef USE_LOOP_UNROLLING

    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    if (!p[0])
        return (size_t)(p - s);
    if (!p[1])
        return (size_t)(p - s + 1);
    if (!p[2])
        return (size_t)(p - s + 2);
    if (!p[3])
        return (size_t)(p - s + 3);
    if (!p[4])
        return (size_t)(p - s + 4);
    if (!p[5])
        return (size_t)(p - s + 5);

    /* Unreachable */
    return 0;

#else /* USE_LOOP_UNROLLING */

    size_t n = 0;

    while (*s++)
        n++;

    return n;

#endif /* USE_LOOP_UNROLLING */
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
