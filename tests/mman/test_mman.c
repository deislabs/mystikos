// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <myst/mman.h>

#define D(X)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* the test doesn't link the kernel so we provide this definition */
int myst_tcall_mprotect(void* addr, size_t len, int prot)
{
    return mprotect(addr, len, prot);
}

void __myst_panic(
    const char* file,
    size_t line,
    const char* func,
    const char* format,
    ...)
{
    fprintf(stderr, "*** panic: %s(%zu): %s(): ", file, line, func);
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    abort();
    for (;;)
        ;
}

typedef struct _page
{
    uint8_t buf[4096];
} page_t;

static int _rand(void)
{
    return rand();
}

/* Cound the VADs in the VAD list */
size_t _count_vads(const myst_vad_t* list)
{
    const myst_vad_t* p;
    size_t count = 0;

    for (p = list; p; p = p->next)
        count++;

    return count;
}

/* Initialize the heap object */
static int _init_mman(myst_mman_t* heap, size_t size)
{
    void* base;

    /* Allocate aligned pages */
    if (!(base = memalign(PAGE_SIZE, size)))
    {
        printf("memalign() failed: size=%zu\n", size);
        return -1;
    }

    if (myst_mman_init(heap, (uintptr_t)base, size) != 0)
    {
        printf("ERROR: myst_mman_init(): %s\n", heap->err);
        return -1;
    }

    heap->scrub = true;

    myst_mman_set_sanity(heap, true);

    return 0;
}

/* Free the base of the heap */
static void _free_mman(myst_mman_t* heap)
{
    free((void*)heap->base);
}

/* Check that the VAD list is sorted by starting address */
static bool _is_sorted(const myst_vad_t* list)
{
    const myst_vad_t* p;
    const myst_vad_t* prev = NULL;

    for (p = list; p; prev = p, p = p->next)
    {
        if (prev && !(prev->addr < p->addr))
            return false;
    }

    return true;
}

/* Check that there are no gaps between the VADs in the list */
static bool _is_flush(const myst_mman_t* heap, const myst_vad_t* list)
{
    const myst_vad_t* p;
    const myst_vad_t* prev = NULL;

    if (!list)
        return true;

    if (heap->map != list->addr)
        return false;

    for (p = list; p; prev = p, p = p->next)
    {
        if (prev)
        {
            if (prev->addr + prev->size != p->addr)
                return false;
        }
    }

    if (prev && prev->addr + prev->size != heap->end)
        return false;

    return true;
}

/* Helper for calling myst_mman_mmap() */
static void* _mman_mmap(myst_mman_t* heap, void* addr, size_t length)
{
    int prot = MYST_PROT_READ | MYST_PROT_WRITE;
    int flags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE;

    void* result;

    if (myst_mman_mmap(heap, addr, length, prot, flags, &result) != 0)
    {
        printf("ERROR: myst_mman_mmap(): %s\n", heap->err);
        assert("myst_mman_mmap(): failed" == NULL);
    }

    return result;
}

/* Helper for calling myst_mman_mmap() without printing an error */
static void* _mman_mmap_no_err(myst_mman_t* heap, void* addr, size_t length)
{
    int prot = MYST_PROT_READ | MYST_PROT_WRITE;
    int flags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE;

    void* result = NULL;

    if (myst_mman_mmap(heap, addr, length, prot, flags, &result) != 0)
        return NULL;

    return result;
}

/* Helper for calling myst_mman_mremap() */
static void* _mman_remap(
    myst_mman_t* heap,
    void* addr,
    size_t old_size,
    size_t new_size)
{
    int flags = MYST_MREMAP_MAYMOVE;

    void* result = NULL;

    if (myst_mman_mremap(heap, addr, old_size, new_size, flags, &result) != 0)
    {
        printf("ERROR: myst_mman_mremap(): %s\n", heap->err);
        assert(false);
    }

    return result;
}

/* Helper for calling myst_mman_munmap() */
static int _mman_unmap(myst_mman_t* heap, void* address, size_t size)
{
    int rc = (int)myst_mman_munmap(heap, address, size);

    if (rc != 0)
        printf("ERROR: myst_mman_munmap(): %s\n", heap->err);

    return rc;
}

/* Helper for calling myst_mman_get_prot() */
static int _mman_get_prot(
    myst_mman_t* heap,
    void* address,
    size_t size,
    int* prot,
    bool* consistent)
{
    int rc = myst_mman_get_prot(heap, address, size, prot, consistent);

    if (rc != 0)
    {
        printf("ERROR: myst_mman_get_prot(): %s\n", heap->err);
        assert(false);
    }
    return rc;
}

/* Helper for calling myst_mman_mprotect() */
static int _mman_protect(
    myst_mman_t* heap,
    void* address,
    size_t size,
    int prot)
{
    int rc = myst_mman_mprotect(heap, address, size, prot);

    if (rc != 0)
    {
        printf("ERROR: myst_mman_mprotect(): %s\n", heap->err);
        assert(false);
    }
    return rc;
}

/*
** test_mman_1()
**
**     Test myst_mman_mmap() and myst_mman_munmap() and check expected state
*between
**     operations. Unmap leaves gaps and then map checks to see if those gaps
**     are filled.
*/
void test_mman_1()
{
    // char buf1[4096];
    //(void)buf1;
    myst_mman_t h;
    // char buf2[4096];
    //(void)buf2;

    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    assert(h.initialized == true);
    assert(h.size == size);
    assert(h.base != 0);
    assert((uintptr_t)h.next_vad == h.base);
    assert(h.end_vad == h.next_vad + npages);
    assert((uintptr_t)h.end_vad == h.base + npages * sizeof(myst_vad_t));
    assert(h.brk == h.start);
    assert(h.map == h.end);
    assert(_is_sorted(h.vad_list));

    void* ptrs[16];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    assert(h.brk == h.start);
    assert(h.map == h.end - m);
    assert(_is_sorted(h.vad_list));

    for (size_t i = 0; i < n; i++)
    {
        if (_mman_unmap(&h, ptrs[i], (i + 1) * PAGE_SIZE) != 0)
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    /* Allocate N regions */
    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (_mman_unmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

    assert(_is_sorted(h.vad_list));
    assert(_count_vads(h.vad_list) == n / 2);
    assert(_count_vads(h.free_vads) == 0);

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (_mman_unmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_mman_2()
**
**     Test myst_mman_mmap() and myst_mman_munmap() and check expected state
*between
**     operations. Map several regions and then unmap regions leaving gaps.
**     Map again and see if the new regions were allocated within the expected
**     gaps.
*/
void test_mman_2()
{
    myst_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* p0;
    void* p1;
    void* p2;
    {
        if (!(p0 = _mman_mmap(&h, NULL, 2 * PAGE_SIZE)))
            assert(0);

        if (!(p1 = _mman_mmap(&h, NULL, 3 * PAGE_SIZE)))
            assert(0);

        if (!(p2 = _mman_mmap(&h, NULL, 4 * PAGE_SIZE)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    void* p0a;
    void* p0b;
    {
        if (_mman_unmap(&h, p0, 2 * PAGE_SIZE) != 0)
            assert(0);

        assert(_is_sorted(h.vad_list));
        assert(!_is_flush(&h, h.vad_list));

        if (!(p0a = _mman_mmap(&h, NULL, PAGE_SIZE)))
            assert(0);
        assert(p0a == p0);

        assert(_is_sorted(h.vad_list));

        if (!(p0b = _mman_mmap(&h, NULL, PAGE_SIZE)))
            assert(0);
        assert(p0b == (uint8_t*)p0 + PAGE_SIZE);

        assert(_is_sorted(h.vad_list));
        assert(_is_flush(&h, h.vad_list));
    }

    void* p2a;
    void* p2b;
    {
        if (_mman_unmap(&h, p2, 4 * PAGE_SIZE) != 0)
            assert(0);

        assert(_is_sorted(h.vad_list));
        assert(_is_flush(&h, h.vad_list));

        if (!(p2a = _mman_mmap(&h, NULL, PAGE_SIZE)))
            assert(0);
        assert(p2a == (uint8_t*)p2 + 3 * PAGE_SIZE);

        if (!(p2b = _mman_mmap(&h, NULL, 3 * PAGE_SIZE)))
            assert(0);
        assert(p2b == p2);

        assert(_is_sorted(h.vad_list));
        assert(_is_flush(&h, h.vad_list));
    }

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_mman_3()
**
**     Test mapping N regions. Then free the first 2 regions. Check that
**     subsequent mapping will allocate memory over those leading regions.
**
*/
void test_mman_3()
{
    myst_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    /* ptrs[0] -- 1 page */
    /* ptrs[1] -- 2 page */
    /* ptrs[2] -- 3 page */
    /* ptrs[3] -- 4 page */
    /* ptrs[4] -- 5 page */
    /* ptrs[5] -- 6 page */
    /* ptrs[6] -- 7 page */
    /* ptrs[7] -- 8 page */

    assert(h.brk == h.start);
    assert(h.map == h.end - m);
    assert(_is_sorted(h.vad_list));

    /* This should be illegal since it overruns the end */
    assert(myst_mman_munmap(&h, ptrs[0], 2 * PAGE_SIZE) != 0);
    assert(_is_sorted(h.vad_list));
    assert(_is_flush(&h, h.vad_list));

    /* Unmap ptrs[1] and ptrs[0] */
    if (_mman_unmap(&h, ptrs[1], 3 * PAGE_SIZE) != 0)
        assert(0);

    assert(_is_sorted(h.vad_list));
    assert(!_is_flush(&h, h.vad_list));

    /* ptrs[0] -- 1 page (free) */
    /* ptrs[1] -- 2 page (free) */
    /* ptrs[2] -- 3 page */
    /* ptrs[3] -- 4 page */
    /* ptrs[4] -- 5 page */
    /* ptrs[5] -- 6 page */
    /* ptrs[6] -- 7 page */
    /* ptrs[7] -- 8 page */

    /* Free innner 6 pages of ptrs[7] -- [mUUUUUUm] */
    if (_mman_unmap(&h, (uint8_t*)ptrs[7] + PAGE_SIZE, 6 * PAGE_SIZE) != 0)
        assert(0);

    assert(_is_sorted(h.vad_list));

    /* Map 6 pages to fill the gap created by last unmap */
    if (!_mman_mmap(&h, NULL, 6 * PAGE_SIZE))
        assert(0);

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_mman_4()
**
**     Perform mapping and then negative test to unmap memory that is not
**     validly mapped.
**
*/
void test_mman_4()
{
    myst_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    assert(h.brk == h.start);
    assert(h.map == h.end - m);
    assert(_is_sorted(h.vad_list));

    /* This should fail */
    assert(myst_mman_munmap(&h, ptrs[7], 1024 * PAGE_SIZE) != 0);

    /* Unmap everything */
    assert(_mman_unmap(&h, ptrs[7], m) == 0);

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_mman_5()
**
**     Perform mapping of separate regions and then try unmapping the entire
**     space with a single unmap.
**
*/
void test_mman_5()
{
    myst_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    /* Unmap a region in the middle */
    assert(_mman_unmap(&h, ptrs[4], 5 * PAGE_SIZE) == 0);

    /* Unmap everything */
    assert(myst_mman_munmap(&h, ptrs[7], m) != 0);

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_mman_6()
**
**     Perform mapping of large segment and then try unmapping that segment
**     with several unmaps of smaller regions.
**
*/
void test_mman_6()
{
    myst_mman_t h;
    size_t i;
    const size_t n = 8;
    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;

    assert(_init_mman(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    if (!(ptr = _mman_mmap(&h, NULL, n * PAGE_SIZE)))
        assert(0);

    /* Unmap 8 pages, 1 page at a time */
    for (i = 0; i < n; i++)
    {
        void* p = (uint8_t*)ptr + (i * PAGE_SIZE);
        assert(_mman_unmap(&h, p, PAGE_SIZE) == 0);
    }

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_mman_7()
**
**     mmap with preferred address, without setting MAP_FIXED
**
*/
#define PREFERRED_ADDR 0x400000
void test_mman_7()
{
    myst_mman_t h;
    size_t i;
    const size_t n = 8;
    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;

    assert(_init_mman(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    if (!(ptr = _mman_mmap(&h, (void*)PREFERRED_ADDR, n * PAGE_SIZE)))
        assert(0);

    /* Unmap 8 pages, 1 page at a time */
    for (i = 0; i < n; i++)
    {
        void* p = (uint8_t*)ptr + (i * PAGE_SIZE);
        assert(_mman_unmap(&h, p, PAGE_SIZE) == 0);
    }

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_remap_1()
**
**     Test remap that enlarges the allocation. Then test remap that shrinks
**     the region.
**
*/
void test_remap_1()
{
    myst_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    assert(_init_mman(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    old_size = 8 * PAGE_SIZE;
    if (!(ptr = _mman_mmap(&h, NULL, old_size)))
        assert(0);

    assert(_is_sorted(h.vad_list));
    assert(_is_flush(&h, h.vad_list));

    /* Remap region, making it twice as big */
    new_size = 16 * PAGE_SIZE;
    if (!(ptr = _mman_remap(&h, ptr, old_size, new_size)))
    {
        assert(0);
    }

    assert(_is_sorted(h.vad_list));
    assert(!_is_flush(&h, h.vad_list));

    /* Remap region, making it four times smaller */
    old_size = new_size;
    new_size = 4 * PAGE_SIZE;
    if (!(ptr = _mman_remap(&h, ptr, old_size, new_size)))
        assert(0);

    assert(_is_sorted(h.vad_list));
    assert(!_is_flush(&h, h.vad_list));

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_remap_2()
**
**     Map two regions so that they are contiguous. Then try remapping the
**     combined region, making it bigger.
**
*/
void test_remap_2()
{
    myst_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    assert(_init_mman(&h, size) == 0);

    /* Map N pages */
    old_size = 8 * PAGE_SIZE;
    void* ptr1;
    if (!(ptr1 = _mman_mmap(&h, NULL, old_size)))
        assert(0);

    /* Map N pages */
    old_size = 8 * PAGE_SIZE;
    void* ptr2;
    if (!(ptr2 = _mman_mmap(&h, NULL, old_size)))
        assert(0);

    /* Remap region, making it twice as big */
    new_size = 16 * PAGE_SIZE;
    if (!(ptr2 = _mman_remap(&h, ptr2, old_size, new_size)))
        assert(0);

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_remap_3()
**
**     Map two regions so that they are contiguous. Remap trailing portion of
**     combined region, make it lareger.
**
*/
void test_remap_3()
{
    myst_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;

    assert(_init_mman(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    page_t* ptr1;
    if (!(ptr1 = (page_t*)_mman_mmap(&h, NULL, 4 * PAGE_SIZE)))
        assert(0);

    /* Map 4 pages: [0|1|2|3] */
    page_t* ptr2;
    if (!(ptr2 = (page_t*)_mman_mmap(&h, NULL, 4 * PAGE_SIZE)))
        assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    assert(ptr2 + 4 == ptr1);

    /* Set pointer to overlapped region: [3|4] */
    page_t* ptr3 = ptr2 + 3;

    /* Shrink region: [3|4] */
    if (!(ptr3 = (page_t*)_mman_remap(&h, ptr3, 2 * PAGE_SIZE, 1 * PAGE_SIZE)))
        assert(0);

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_remap_4()
**
**     Map two regions so that they are contiguous. Unmap trailing porition
**     of combined regions.
**
*/
void test_remap_4()
{
    myst_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * PAGE_SIZE;

    assert(_init_mman(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    page_t* ptr1;
    if (!(ptr1 = (page_t*)_mman_mmap(&h, NULL, 4 * PAGE_SIZE)))
        assert(0);

    /* Map 4 pages: [0|1|2|3] */
    page_t* ptr2;
    if (!(ptr2 = (page_t*)_mman_mmap(&h, NULL, 4 * PAGE_SIZE)))
        assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    assert(ptr2 + 4 == ptr1);

    /* Unmap [4|5|6|7] */
    assert(_mman_unmap(&h, ptr1, 4 * PAGE_SIZE) == 0);

    page_t* ptr3 = ptr2 + 2;

    /* Expand region: [2|3] */
    if (!(ptr3 = (page_t*)_mman_remap(&h, ptr3, 2 * PAGE_SIZE, 4 * PAGE_SIZE)))
        assert(0);

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

typedef struct _elem
{
    void* addr;
    size_t size;
} elem_t;

static void _set_mem(elem_t* elem)
{
    uint8_t* p = (uint8_t*)elem->addr;
    const size_t n = elem->size;

    for (size_t i = 0; i < n; i++)
    {
        p[i] = (uint8_t)(n % 251);
    }
}

static bool _check_mem(elem_t* elem)
{
    const uint8_t* p = (const uint8_t*)elem->addr;
    const size_t n = elem->size;

    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != (uint8_t)(n % 251))
            return false;
    }

    return true;
}

/*
** test_mman_randomly()
**
**     Test random allocation of memory. Loop such that each iteration
**     randomly chooses to map, unmap, or remap memory. Finally unmap
**     all memory.
*/
void test_mman_randomly()
{
    myst_mman_t h;
    const size_t heap_size = 64 * 1024 * 1024;

    assert(_init_mman(&h, heap_size) == 0);

    static elem_t elem[1024];
    const size_t N = sizeof(elem) / sizeof(elem[0]);
    // const size_t M = 20000;
    const size_t M = 1000;

    for (size_t i = 0; i < M; i++)
    {
        size_t r = (size_t)_rand() % N;

        if (elem[r].addr)
        {
            assert(_check_mem(&elem[r]));

            if (_rand() % 2)
            {
                D(printf(
                      "unmap: addr=%p size=%zu\n", elem[r].addr, elem[r].size);)

                assert(_mman_unmap(&h, elem[r].addr, elem[r].size) == 0);
                elem[r].addr = NULL;
                elem[r].size = 0;
            }
            else
            {
                void* addr = elem[r].addr;
                assert(addr);

                size_t old_size = elem[r].size;
                assert(old_size > 0);

                size_t new_size = (size_t)(_rand() % 16 + 1) * PAGE_SIZE;
                assert(new_size > 0);

                D(printf(
                      "remap: addr=%p old_size=%zu new_size=%zu\n",
                      addr,
                      old_size,
                      new_size);)

                addr = _mman_remap(&h, addr, old_size, new_size);
                assert(addr);

                elem[r].addr = addr;
                elem[r].size = new_size;
                _set_mem(&elem[r]);
            }
        }
        else
        {
            size_t size = (size_t)(_rand() % 16 + 1) * PAGE_SIZE;
            assert(size > 0);

            void* addr = _mman_mmap(&h, NULL, size);
            assert(addr);

            D(printf("map: addr=%p size=%zu\n", addr, size);)

            elem[r].addr = addr;
            elem[r].size = size;
            _set_mem(&elem[r]);
        }
    }

    /* Unmap all remaining memory */
    for (size_t i = 0; i < N; i++)
    {
        if (elem[i].addr)
        {
            D(printf("addr=%p size=%zu\n", elem[i].addr, elem[i].size);)
            assert(_check_mem(&elem[i]));
            assert(_mman_unmap(&h, elem[i].addr, elem[i].size) == 0);
        }
    }

    /* Everything should be unmapped */
    assert(h.vad_list == NULL);

    assert(myst_mman_is_sane(&h));

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_out_of_memory()
**
**     Loop while mapping memory until all memory is exhausted.
**
*/
void test_out_of_memory()
{
    myst_mman_t h;
    const size_t heap_size = 64 * 1024 * 1024;

    assert(_init_mman(&h, heap_size) == 0);

    /* Use up all the memory */
    while (_mman_mmap_no_err(&h, NULL, 64 * PAGE_SIZE))
        ;

    assert(myst_mman_is_sane(&h));

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_prot_vector()
**
**     Test prot_vector tracking of the permission prot.
**
*/
void test_prot_vector()
{
    myst_mman_t h;
    const size_t heap_size = 64 * 1024 * 1024;
    int prot = MYST_PROT_READ | MYST_PROT_WRITE;
    int prot_val = MYST_PROT_NONE;
    int flags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE;
    void *addr1, *addr2, *addr3, *addr4, *addr5;
    size_t len1, len2;
    bool consistent;
    void* brk = NULL;
    uint8_t zero_page[PAGE_SIZE];
    uint8_t ff_page[PAGE_SIZE];
    int i;

    memset(zero_page, 0, PAGE_SIZE);
    memset(ff_page, 0xff, PAGE_SIZE);

    assert(_init_mman(&h, heap_size) == 0);
    /* verify unassigned memory default permission as MYST_PROT_NONE */
    assert(
        (_mman_get_prot(
            &h, (void*)h.start, (h.end - h.start), &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PROT_NONE);
    assert(consistent == true);

#define MYST_PENDING_ZEROING_FLAG 0x80
    /* reserve 16 pages as prot = MYST_PROT_NONE */
    if (myst_mman_mmap(
            &h, NULL, 16 * PAGE_SIZE, MYST_PROT_NONE, flags, &addr1) != 0)
    {
        printf("ERROR: myst_mman_mmap(): %s\n", h.err);
        assert("myst_mman_mmap(): failed" == NULL);
    }
    /* verify the mapped 16 pages permission as MYST_PENDING_ZEROING_FLAG */
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PENDING_ZEROING_FLAG);
    assert(consistent == true);
    /* Increase the mapping permission */
    assert(
        (_mman_protect(
            &h, addr1, 16 * PAGE_SIZE, (MYST_PROT_READ | MYST_PROT_WRITE))) ==
        0);
    /* verify the mapped 16 pages permission as the increased permission */
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE));
    assert(consistent == true);
    /* verify the content of the pages are zero */
    for (i = 0; i < 16; i++)
    {
        assert(!memcmp(addr1 + i * PAGE_SIZE, zero_page, PAGE_SIZE));
    }
    /* write to the pages */
    memset(addr1, 0xDD, 16 * PAGE_SIZE);
    /* map the allocated pages again, as MYST_PROT_NONE */
    if (myst_mman_mmap(
            &h, addr1, 16 * PAGE_SIZE, MYST_PROT_NONE, flags, &addr2) != 0)
    {
        printf("ERROR: myst_mman_mmap(): %s\n", h.err);
        assert("myst_mman_mmap(): failed" == NULL);
    }
    assert(addr2 == addr1);
    /* verify the mapped 16 pages permission as MYST_PENDING_ZEROING_FLAG */
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PENDING_ZEROING_FLAG);
    assert(consistent == true);
    /* mprotect(MYST_PROT_NONE), making sure the MYST_PENDING_ZEROING_FLAG
      is not cleared */
    assert((_mman_protect(&h, addr1, 16 * PAGE_SIZE, MYST_PROT_NONE)) == 0);
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PENDING_ZEROING_FLAG);
    assert(consistent == true);

    /* mprotect(MYST_PROT_READ), which should trigger delayed zero-fill */
    assert((_mman_protect(&h, addr1, 16 * PAGE_SIZE, MYST_PROT_READ)) == 0);
    /* verify the content of the pages are zero */
    for (i = 0; i < 16; i++)
    {
        assert(!memcmp(addr1 + i * PAGE_SIZE, zero_page, PAGE_SIZE));
    }

    _mman_unmap(&h, addr1, 16 * PAGE_SIZE);

    /* map 16 pages as prot = MYST_PROT_READ | MYST_PROT_WRITE */
    if (myst_mman_mmap(&h, NULL, 16 * PAGE_SIZE, prot, flags, &addr1) != 0)
    {
        printf("ERROR: myst_mman_mmap(): %s\n", h.err);
        assert("myst_mman_mmap(): failed" == NULL);
    }
    /* verify the mapped 16 pages permission as prot */
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == prot);
    assert(consistent == true);
    /* verify the content of the pages are zero */
    for (i = 0; i < 16; i++)
    {
        assert(!memcmp(addr1 + i * PAGE_SIZE, zero_page, PAGE_SIZE));
    }

    /* Reduce the mapping permission */
    assert((_mman_protect(&h, addr1, 16 * PAGE_SIZE, MYST_PROT_READ)) == 0);
    /* verify the mapped 16 pages permission as the reduced permission */
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PROT_READ);
    assert(consistent == true);

    /* Increase the mapping permission */
    assert(
        (_mman_protect(
            &h, addr1, 16 * PAGE_SIZE, MYST_PROT_READ | MYST_PROT_WRITE)) == 0);
    /* verify the mapped 16 pages permission as the increased permission */
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE));
    assert(consistent == true);

    /* Increase the mapping permission */
    assert(
        (_mman_protect(
            &h,
            addr1,
            16 * PAGE_SIZE,
            MYST_PROT_READ | MYST_PROT_WRITE | MYST_PROT_EXEC)) == 0);
    /* verify the mapped 16 pages permission as the increased permission */
    assert(
        (_mman_get_prot(&h, addr1, 16 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE | MYST_PROT_EXEC));
    assert(consistent == true);

    prot = MYST_PROT_READ | MYST_PROT_WRITE | MYST_PROT_EXEC;

    /* unmap the first page from the block */
    assert(_mman_unmap(&h, addr1, PAGE_SIZE) == 0);
    /* verified the unmapped page permission as MYST_PROT_NONE */
    assert((_mman_get_prot(&h, addr1, PAGE_SIZE, &prot_val, &consistent)) == 0);
    assert(prot_val == MYST_PROT_NONE);

    addr1 = addr1 + PAGE_SIZE;

    /* verified the remaining mapped 15 pages permission as prot */
    assert(
        (_mman_get_prot(&h, addr1, 15 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == prot);
    assert(consistent == true);

    /* unmap a middle 2 pages from the block */
    assert(_mman_unmap(&h, addr1 + 8 * PAGE_SIZE, 2 * PAGE_SIZE) == 0);

    addr2 = addr1 + 10 * PAGE_SIZE;
    len1 = 8 * PAGE_SIZE;
    len2 = 5 * PAGE_SIZE;

    /* verify the unmapped 2 pages permission as MYST_PROT_NONE */
    assert(
        (_mman_get_prot(
            &h,
            (addr1 + 8 * PAGE_SIZE),
            2 * PAGE_SIZE,
            &prot_val,
            &consistent)) == 0);
    assert(prot_val == MYST_PROT_NONE);
    assert(consistent == true);

    /* verify the block before the unmapped 2 pages permission as prot */
    assert((_mman_get_prot(&h, addr1, len1, &prot_val, &consistent)) == 0);
    assert(prot_val == prot);
    assert(consistent == true);
    /* verify the block after the unmapped 2 pages permission as prot */
    assert((_mman_get_prot(&h, addr2, len2, &prot_val, &consistent)) == 0);
    assert(prot_val == prot);
    assert(consistent == true);

    /* check prot tracking block inconsistency detection */
    assert(
        (_mman_get_prot(&h, addr1, 15 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(consistent == false);

    /* remap addr1 to expand 1 page */
    if (!(addr1 = _mman_remap(&h, addr1, len1, len1 + PAGE_SIZE)))
    {
        assert(0);
    }
    len1 = len1 + PAGE_SIZE;
    /* verify the expanded block permission as prot */
    assert((_mman_get_prot(&h, addr1, len1, &prot_val, &consistent)) == 0);
    assert(prot_val == prot);
    assert(consistent == true);

    /* reallocate addr1 to to a new block */
    if (!(addr3 = _mman_remap(&h, addr1, len1, 63 * PAGE_SIZE)))
    {
        assert(0);
    }
    /* verify the reallocated block permission as prot */
    assert(
        (_mman_get_prot(&h, addr3, 63 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == prot);
    assert(consistent == true);
    /* verify the deallocated block permission as MYST_PROT_NONE */
    assert((_mman_get_prot(&h, addr1, len1, &prot_val, &consistent)) == 0);
    assert(prot_val == MYST_PROT_NONE);
    assert(consistent == true);

    // remap reallocation/copy without W permission
    assert((_mman_protect(&h, addr3, 63 * PAGE_SIZE, MYST_PROT_READ)) == 0);
    /* reallocate addr3 to to a new block */
    if (!(addr4 = _mman_remap(&h, addr3, 63 * PAGE_SIZE, 127 * PAGE_SIZE)))
    {
        assert(0);
    }
    assert(
        (_mman_get_prot(&h, addr4, 127 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PROT_READ);
    assert(consistent == true);

    // remap reallocation/copy without R permission
    assert((_mman_protect(&h, addr4, 127 * PAGE_SIZE, MYST_PROT_WRITE)) == 0);
    /* reallocate addr4 to to a new block */
    if (!(addr5 = _mman_remap(&h, addr4, 127 * PAGE_SIZE, 255 * PAGE_SIZE)))
    {
        assert(0);
    }
    assert(
        (_mman_get_prot(&h, addr5, 255 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PROT_WRITE);
    assert(consistent == true);

    /* umap everything */
    _mman_unmap(&h, addr5, 255 * PAGE_SIZE);
    _mman_unmap(&h, addr2, len2);
    /* verify the unassigned memory permission as MYST_PROT_NONE */
    assert(
        (_mman_get_prot(
            &h, (void*)h.start, (h.end - h.start), &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PROT_NONE);
    assert(consistent == true);

    // test corner case re-map
    if (myst_mman_mmap(
            &h, NULL, 16 * PAGE_SIZE, MYST_PROT_NONE, flags, &addr1) != 0)
    {
        printf("ERROR: myst_mman_mmap(): %s\n", h.err);
        assert("myst_mman_mmap(): failed" == NULL);
    }
    assert(
        (_mman_protect(
            &h, addr1 + 4 * PAGE_SIZE, 8 * PAGE_SIZE, MYST_PROT_WRITE)) == 0);
    memset(addr1 + 4 * PAGE_SIZE, 0xff, 8 * PAGE_SIZE);
    assert(
        (_mman_protect(
            &h, addr1 + 4 * PAGE_SIZE, 8 * PAGE_SIZE, MYST_PROT_NONE)) == 0);
    assert(
        (_mman_get_prot(
            &h,
            addr1 + 4 * PAGE_SIZE,
            8 * PAGE_SIZE,
            &prot_val,
            &consistent)) == 0);
    assert(prot_val == MYST_PROT_NONE);
    assert(consistent == true);
    /* reallocate addr1 to to a new block */
    if (!(addr2 = _mman_remap(&h, addr1, 16 * PAGE_SIZE, 31 * PAGE_SIZE)))
    {
        assert(0);
    }
    assert(
        (_mman_get_prot(&h, addr2, 31 * PAGE_SIZE, &prot_val, &consistent)) ==
        0);
    assert(prot_val == MYST_PROT_NONE);
    assert(consistent == true);
    assert((_mman_protect(&h, addr2, 31 * PAGE_SIZE, MYST_PROT_READ)) == 0);
    /* verify the content of the first 4 pages are zero */
    for (i = 0; i < 4; i++)
    {
        assert(!memcmp(addr2 + i * PAGE_SIZE, zero_page, PAGE_SIZE));
    }
    /* verify the content of the next 8 pages are 0xff */
    for (i = 4; i < 4 + 8; i++)
    {
        assert(!memcmp(addr2 + i * PAGE_SIZE, ff_page, PAGE_SIZE));
    }
    /* verify the rest of the pages are zero */
    for (i = 12; i < 31; i++)
    {
        assert(!memcmp(addr2 + i * PAGE_SIZE, zero_page, PAGE_SIZE));
    }

    /* create 4 pages BRK region */
    if (myst_mman_sbrk(&h, 4 * PAGE_SIZE, &brk))
    {
        printf("ERROR: myst_mman_sbrk(): %s\n", h.err);
        assert("myst_mman_sbrk: failed" == NULL);
    }
    /* verify BRK region permission as MYST_PROT_READ | MYST_PROT_WRITE */
    assert(
        (_mman_get_prot(
            &h, (void*)h.start, 4 * PAGE_SIZE, &prot_val, &consistent)) == 0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE));
    assert(consistent == true);
    /* verify the page after BRK region permission as MYST_PROT_NONE */
    assert(
        (_mman_get_prot(
            &h,
            (void*)(h.start + 4 * PAGE_SIZE),
            PAGE_SIZE,
            &prot_val,
            &consistent)) == 0);
    assert(prot_val == MYST_PROT_NONE);

    /* increase BRK region by 8 byte */
    if (myst_mman_sbrk(&h, 8, &brk))
    {
        printf("ERROR: myst_mman_sbrk(): %s\n", h.err);
        assert("myst_mman_sbrk: failed" == NULL);
    }
    /* verify the 8 byte extra causes next Page permission to be MYST_PROT_READ
     * | MYST_PROT_WRITE */
    assert(
        (_mman_get_prot(
            &h, (void*)h.start, 5 * PAGE_SIZE, &prot_val, &consistent)) == 0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE));
    assert(consistent == true);

    /* shrink PRK region to 3 pages */
    if (myst_mman_brk(&h, (void*)(h.start + 3 * PAGE_SIZE), &brk))
    {
        printf("ERROR: myst_mman_sbrk(): %s\n", h.err);
        assert("myst_mman_sbrk: failed" == NULL);
    }
    /* verify the shrinked BRK region permission as MYST_PROT_READ |
     * MYST_PROT_WRITE */
    assert(
        (_mman_get_prot(
            &h, (void*)h.start, 3 * PAGE_SIZE, &prot_val, &consistent)) == 0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE));
    assert(consistent == true);
    /* verify the page after BRK region permission as MYST_PROT_NONE */
    assert(
        (_mman_get_prot(
            &h,
            (void*)(h.start + 4 * PAGE_SIZE),
            PAGE_SIZE,
            &prot_val,
            &consistent)) == 0);
    assert(prot_val == MYST_PROT_NONE);

    /* Shrink PRK region size to 2 pages plus 8 byte */
    if (myst_mman_brk(&h, (void*)(h.start + 2 * PAGE_SIZE + 8), &brk))
    {
        printf("ERROR: myst_mman_sbrk(): %s\n", h.err);
        assert("myst_mman_sbrk: failed" == NULL);
    }
    /* verify the extra 8 byte cause the page permission as MYST_PROT_READ |
     * MYST_PROT_WRITE*/
    assert(
        (_mman_get_prot(
            &h,
            (void*)(h.start + 2 * PAGE_SIZE),
            PAGE_SIZE,
            &prot_val,
            &consistent)) == 0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE));

    /* Increase PRK region size to 10 pages plus 8 byte */
    if (myst_mman_brk(&h, (void*)(h.start + 10 * PAGE_SIZE + 8), &brk))
    {
        printf("ERROR: myst_mman_sbrk(): %s\n", h.err);
        assert("myst_mman_sbrk: failed" == NULL);
    }
    /* verify the 10 Pages plus 8 byte BRK region cause 11 pages permission as
     * MYST_PROT_READ | MYST_PROT_WRITE */
    assert(
        (_mman_get_prot(
            &h, (void*)h.start, 11 * PAGE_SIZE, &prot_val, &consistent)) == 0);
    assert(prot_val == (MYST_PROT_READ | MYST_PROT_WRITE));
    assert(consistent == true);

    assert(myst_mman_is_sane(&h));

    _free_mman(&h);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_mman(void)
{
    test_mman_1();
    test_mman_2();
    test_mman_3();
    test_mman_4();
    test_mman_5();
    test_mman_6();
    test_mman_7();
    test_remap_1();
    test_remap_2();
    test_remap_3();
    test_remap_4();
    test_out_of_memory();
    test_mman_randomly();
    test_prot_vector();
}
