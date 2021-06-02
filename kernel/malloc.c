// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
**==============================================================================
**
** This source file wraps Doug Lea's dlmalloc application, which is included
** in the Mystikos source tree here along with a copy of the license.
**
**     ../third_party/dlmalloc
**
** A copy of the dlmalloc license can be found here:
**
**     ../third_party/dlmalloc/LICENSE
**
**==============================================================================
*/

#include <limits.h>
#include <sys/mman.h>

#include <myst/backtrace.h>
#include <myst/crash.h>
#include <myst/debugmalloc.h>
#include <myst/kernel.h>
#include <myst/list.h>
#include <myst/malloc.h>
#include <myst/mmanutils.h>
#include <myst/panic.h>
#include <myst/printf.h>

static void _dlmalloc_abort(void)
{
    myst_panic("dlmalloc failed");
}

static int _dlmalloc_sched_yield(void)
{
    __asm__ __volatile__("pause" : : : "memory");
    return 0;
}

static void* _dlmalloc_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    long r = (long)myst_mmap(addr, length, prot, flags, fd, offset);

    if (r < 0)
    {
        errno = -r;
        return MAP_FAILED;
    }

    return (void*)r;
}

static void* _dlmalloc_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    ...)
{
    /* ATTN: new_address is ignored */
    long r = (long)myst_mremap(old_address, old_size, new_size, flags, NULL);

    if (r < 0)
    {
        errno = -r;
        return MAP_FAILED;
    }

    return (void*)r;
}

static int _dlmalloc_munmap(void* addr, size_t length)
{
    int ret;

    if ((ret = myst_munmap(addr, length)) < 0)
    {
        errno = -ret;
        ret = -1;
    }

    return ret;
}

#define abort _dlmalloc_abort
#define sched_yield _dlmalloc_sched_yield
#define mmap _dlmalloc_mmap
#define mremap _dlmalloc_mremap
#define munmap _dlmalloc_munmap
#define USE_LOCKS 1
#define HAVE_MORECORE 0
#define malloc_getpagesize PAGE_SIZE
#define MORECORE_CONTIGUOUS 0
#define fprintf(STREAM, ...) myst_eprintf(__VA_ARGS__)
#define USE_DL_PREFIX 0

#include "../third_party/dlmalloc/malloc.c"

#define MAX_BACKTRACE_ADDRS 16

void* myst_malloc(size_t size)
{
    return dlmalloc(size);
}

void* myst_calloc(size_t nmemb, size_t size)
{
    return dlcalloc(nmemb, size);
}

void* myst_realloc(void* ptr, size_t size)
{
    return dlrealloc(ptr, size);
}

void* myst_memalign(size_t alignment, size_t size)
{
    return dlmemalign(alignment, size);
}

int myst_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return dlposix_memalign(memptr, alignment, size);
}

void myst_free(void* ptr)
{
    dlfree(ptr);
}

/*
**==============================================================================
**
** Standard definitions
**
**==============================================================================
*/

void* malloc(size_t size)
{
    if (myst_enable_debug_malloc)
        return myst_debug_malloc(size);
    else
        return myst_malloc(size);
}

void free(void* ptr)
{
    if (myst_enable_debug_malloc)
        myst_debug_free(ptr);
    else
        myst_free(ptr);
}

void* calloc(size_t nmemb, size_t size)
{
    if (myst_enable_debug_malloc)
        return myst_debug_calloc(nmemb, size);
    else
        return myst_calloc(nmemb, size);
}

void* realloc(void* ptr, size_t size)
{
    if (myst_enable_debug_malloc)
        return myst_debug_realloc(ptr, size);
    else
        return myst_realloc(ptr, size);
}

void* memalign(size_t alignment, size_t size)
{
    if (myst_enable_debug_malloc)
        return myst_debug_memalign(alignment, size);
    else
        return myst_memalign(alignment, size);
}

int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    if (myst_enable_debug_malloc)
        return myst_debug_posix_memalign(memptr, alignment, size);
    else
        return myst_posix_memalign(memptr, alignment, size);
}

char* myst_strdup(const char* s)
{
    char* p;

    if (!s)
        return NULL;

    size_t n = strlen(s);

    if (!(p = myst_malloc(n + 1)))
        return NULL;

    return memcpy(p, s, n + 1);
}
