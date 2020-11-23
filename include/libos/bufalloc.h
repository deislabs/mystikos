// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_BUFALLOC_H
#define _LIBOS_BUFALLOC_H

#include <libos/defs.h>
#include <stdlib.h>

/*
**==============================================================================
**
** These functions can be used to avoid dynamic memory allocation in cases
** where the desired allocation size is smaller than a local buffer. For
** example:
**
**     #include <libos/bufalloc.h>
**     #include <errno.h>
**
**     int f(size_t size)
**     {
**         char buf[128];
**         void* p;
**
**         if (!(p = libos_buf_malloc(buf, sizeof(buf), size)))
**             return -ENOMEM;
**         ...
**
**         libos_buf_free(buf, p);
**         return 0;
**     }
**
**==============================================================================
*/

/* return buf if size <= buflen; else return heap-allocated memory */
LIBOS_INLINE void* libos_buf_malloc(void* buf, size_t buflen, size_t size)
{
    if (buf && size && size <= buflen)
        return buf;
    else
        return malloc(size);
}

/* return buf if size <= buflen; else return cleared heap-allocated memory */
LIBOS_INLINE void* libos_buf_calloc(
    void* buf,
    size_t buflen,
    size_t nmemb,
    size_t size)
{
    const size_t n;

    /* check for overflow */
    if (__builtin_mul_overflow(nmemb, size, &n))
        return NULL;

    if (buf && n && n <= buflen)
        return buf;
    else
        return calloc(nmemb, size);
}

/* if buf != ptr, then pass ptr to free() */
LIBOS_INLINE void libos_buf_free(void* buf, void* ptr)
{
    if (buf != ptr)
        free(ptr);
}

#endif /* _LIBOS_BUFALLOC_H */
