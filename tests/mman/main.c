// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <malloc.h>
#include <openenclave/internal/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define D(X)

static size_t PGSZ = OE_PAGE_SIZE;

static bool _coverage[OE_MMAN_COVERAGE_N];

/* Merge heap implementation coverage branches into _coverage[] variable */
static void _merge_coverage(const oe_mman_t* heap)
{
    for (size_t i = 0; i < OE_MMAN_COVERAGE_N; i++)
    {
        if (heap->coverage[i])
        {
            _coverage[i] = true;
        }
    }
}

/* Check that all branches were reached in the heap implementation */
static void _check_coverage()
{
    for (size_t i = 0; i < OE_MMAN_COVERAGE_N; i++)
    {
        if (!_coverage[i])
        {
            fprintf(stderr, "*** uncovered: OE_MMAN_COVERAGE_%zu\n", i);
            assert(0);
        }
        else
        {
            printf("=== passed OE_MMAN_COVERAGE_%zu\n", i);
        }
    }
}

/* Cound the VADs in the VAD list */
size_t _count_vads(const oe_vad_t* list)
{
    const oe_vad_t* p;
    size_t count = 0;

    for (p = list; p; p = p->next)
        count++;

    return count;
}

/* Initialize the heap object */
static int _init_mman(oe_mman_t* heap, size_t size)
{
    void* base;

    /* Allocate aligned pages */
    if (!(base = memalign(OE_PAGE_SIZE, size)))
        return -1;

    if (oe_mman_init(heap, (uintptr_t)base, size) != OE_OK)
    {
        fprintf(stderr, "ERROR: oe_mman_init(): %s\n", heap->err);
        return -1;
    }

    heap->scrub = true;

    oe_mman_set_sanity(heap, true);

    return 0;
}

/* Free the base of the heap */
static void _free_mman(oe_mman_t* heap)
{
    free((void*)heap->base);
}

/* Check that the VAD list is sorted by starting address */
static bool _is_sorted(const oe_vad_t* list)
{
    const oe_vad_t* p;
    const oe_vad_t* prev = NULL;

    for (p = list; p; prev = p, p = p->next)
    {
        if (prev && !(prev->addr < p->addr))
            return false;
    }

    return true;
}

/* Check that there are no gaps between the VADs in the list */
static bool _is_flush(const oe_mman_t* heap, const oe_vad_t* list)
{
    const oe_vad_t* p;
    const oe_vad_t* prev = NULL;

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

/* Helper for calling oe_mman_map() */
static void* _mman_mmap(oe_mman_t* heap, void* addr, size_t length)
{
    int prot = OE_PROT_READ | OE_PROT_WRITE;
    int flags = OE_MAP_ANONYMOUS | OE_MAP_PRIVATE;

    void* result = oe_mman_map(heap, addr, length, prot, flags);

    if (!result)
        fprintf(stderr, "ERROR: oe_mman_map(): %s\n", heap->err);

    return result;
}

/* Helper for calling oe_mman_map() without printing an error */
static void* _mman_mmap_no_err(oe_mman_t* heap, void* addr, size_t length)
{
    int prot = OE_PROT_READ | OE_PROT_WRITE;
    int flags = OE_MAP_ANONYMOUS | OE_MAP_PRIVATE;

    void* result = oe_mman_map(heap, addr, length, prot, flags);

    return result;
}

/* Helper for calling oe_mman_mremap() */
static void* _mman_remap(
    oe_mman_t* heap,
    void* addr,
    size_t old_size,
    size_t new_size)
{
    int flags = OE_MREMAP_MAYMOVE;

    void* result = oe_mman_mremap(heap, addr, old_size, new_size, flags);

    if (!result)
        fprintf(stderr, "ERROR: oe_mman_mremap(): %s\n", heap->err);

    return result;
}

/* Helper for calling oe_mman_munmap() */
static int _mman_unmap(oe_mman_t* heap, void* address, size_t size)
{
    int rc = (int)oe_mman_munmap(heap, address, size);

    if (rc != 0)
        fprintf(stderr, "ERROR: oe_mman_munmap(): %s\n", heap->err);

    return rc;
}

/*
** test_mman_1()
**
**     Test oe_mman_map() and oe_mman_munmap() and check expected state between
**     operations. Unmap leaves gaps and then map checks to see if those gaps
**     are filled.
*/
void test_mman_1()
{
    // char buf1[4096];
    //(void)buf1;
    oe_mman_t h;
    // char buf2[4096];
    //(void)buf2;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    assert(h.initialized == true);
    assert(h.size == size);
    assert(h.base != 0);
    assert((uintptr_t)h.next_vad == h.base);
    assert(h.end_vad == h.next_vad + npages);
    assert(h.start == (uintptr_t)h.end_vad);
    assert(h.brk == h.start);
    assert(h.map == h.end);
    assert(_is_sorted(h.vad_list));

    void* ptrs[16];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    assert(h.brk == h.start);
    assert(h.map == h.end - m);
    assert(_is_sorted(h.vad_list));

    for (size_t i = 0; i < n; i++)
    {
        if (_mman_unmap(&h, ptrs[i], (i + 1) * PGSZ) != 0)
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    /* Allocate N regions */
    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (_mman_unmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

    assert(_is_sorted(h.vad_list));
    assert(_count_vads(h.vad_list) == n / 2);
    assert(_count_vads(h.free_vads) == 0);

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (_mman_unmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

/*
** test_mman_2()
**
**     Test oe_mman_map() and oe_mman_munmap() and check expected state between
**     operations. Map several regions and then unmap regions leaving gaps.
**     Map again and see if the new regions were allocated within the expected
**     gaps.
*/
void test_mman_2()
{
    oe_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* p0;
    void* p1;
    void* p2;
    {
        if (!(p0 = _mman_mmap(&h, NULL, 2 * OE_PAGE_SIZE)))
            assert(0);

        if (!(p1 = _mman_mmap(&h, NULL, 3 * OE_PAGE_SIZE)))
            assert(0);

        if (!(p2 = _mman_mmap(&h, NULL, 4 * OE_PAGE_SIZE)))
            assert(0);
    }

    assert(_is_sorted(h.vad_list));

    void* p0a;
    void* p0b;
    {
        if (_mman_unmap(&h, p0, 2 * OE_PAGE_SIZE) != 0)
            assert(0);

        assert(_is_sorted(h.vad_list));
        assert(!_is_flush(&h, h.vad_list));

        if (!(p0a = _mman_mmap(&h, NULL, OE_PAGE_SIZE)))
            assert(0);
        assert(p0a == p0);

        assert(_is_sorted(h.vad_list));

        if (!(p0b = _mman_mmap(&h, NULL, OE_PAGE_SIZE)))
            assert(0);
        assert(p0b == (uint8_t*)p0 + OE_PAGE_SIZE);

        assert(_is_sorted(h.vad_list));
        assert(_is_flush(&h, h.vad_list));
    }

    void* p2a;
    void* p2b;
    {
        if (_mman_unmap(&h, p2, 4 * OE_PAGE_SIZE) != 0)
            assert(0);

        assert(_is_sorted(h.vad_list));
        assert(_is_flush(&h, h.vad_list));

        if (!(p2a = _mman_mmap(&h, NULL, OE_PAGE_SIZE)))
            assert(0);
        assert(p2a == (uint8_t*)p2 + 3 * OE_PAGE_SIZE);

        if (!(p2b = _mman_mmap(&h, NULL, 3 * OE_PAGE_SIZE)))
            assert(0);
        assert(p2b == p2);

        assert(_is_sorted(h.vad_list));
        assert(_is_flush(&h, h.vad_list));
    }

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
    oe_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

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
    assert(oe_mman_munmap(&h, ptrs[0], 2 * PGSZ) != 0);
    assert(_is_sorted(h.vad_list));
    assert(_is_flush(&h, h.vad_list));

    /* Unmap ptrs[1] and ptrs[0] */
    if (_mman_unmap(&h, ptrs[1], 3 * PGSZ) != 0)
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
    if (_mman_unmap(&h, (uint8_t*)ptrs[7] + PGSZ, 6 * PGSZ) != 0)
        assert(0);

    assert(_is_sorted(h.vad_list));

    /* Map 6 pages to fill the gap created by last unmap */
    if (!_mman_mmap(&h, NULL, 6 * PGSZ))
        assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
    oe_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    assert(h.brk == h.start);
    assert(h.map == h.end - m);
    assert(_is_sorted(h.vad_list));

    /* This should fail */
    assert(oe_mman_munmap(&h, ptrs[7], 1024 * PGSZ) != 0);

    /* Unmap everything */
    assert(_mman_unmap(&h, ptrs[7], m) == 0);

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
    oe_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    /* Unmap a region in the middle */
    assert(_mman_unmap(&h, ptrs[4], 5 * PGSZ) == 0);

    /* Unmap everything */
    assert(oe_mman_munmap(&h, ptrs[7], m) != 0);

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
    oe_mman_t h;
    size_t i;
    const size_t n = 8;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    assert(_init_mman(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    if (!(ptr = _mman_mmap(&h, NULL, n * PGSZ)))
        assert(0);

    /* Unmap 8 pages, 1 page at a time */
    for (i = 0; i < n; i++)
    {
        void* p = (uint8_t*)ptr + (i * PGSZ);
        assert(_mman_unmap(&h, p, PGSZ) == 0);
    }

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
    oe_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    assert(_init_mman(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    old_size = 8 * PGSZ;
    if (!(ptr = _mman_mmap(&h, NULL, old_size)))
        assert(0);

    assert(_is_sorted(h.vad_list));
    assert(_is_flush(&h, h.vad_list));

    /* Remap region, making it twice as big */
    new_size = 16 * PGSZ;
    if (!(ptr = _mman_remap(&h, ptr, old_size, new_size)))
    {
        assert(0);
    }

    assert(_is_sorted(h.vad_list));
    assert(!_is_flush(&h, h.vad_list));

    /* Remap region, making it four times smaller */
    old_size = new_size;
    new_size = 4 * PGSZ;
    if (!(ptr = _mman_remap(&h, ptr, old_size, new_size)))
        assert(0);

    assert(_is_sorted(h.vad_list));
    assert(!_is_flush(&h, h.vad_list));

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
    oe_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    assert(_init_mman(&h, size) == 0);

    /* Map N pages */
    old_size = 8 * PGSZ;
    void* ptr1;
    if (!(ptr1 = _mman_mmap(&h, NULL, old_size)))
        assert(0);

    /* Map N pages */
    old_size = 8 * PGSZ;
    void* ptr2;
    if (!(ptr2 = _mman_mmap(&h, NULL, old_size)))
        assert(0);

    /* Remap region, making it twice as big */
    new_size = 16 * PGSZ;
    if (!(ptr2 = _mman_remap(&h, ptr2, old_size, new_size)))
        assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
    oe_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    assert(_init_mman(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    oe_page_t* ptr1;
    if (!(ptr1 = (oe_page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Map 4 pages: [0|1|2|3] */
    oe_page_t* ptr2;
    if (!(ptr2 = (oe_page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    assert(ptr2 + 4 == ptr1);

    /* Set pointer to overlapped region: [3|4] */
    oe_page_t* ptr3 = ptr2 + 3;

    /* Shrink region: [3|4] */
    if (!(ptr3 = (oe_page_t*)_mman_remap(&h, ptr3, 2 * PGSZ, 1 * PGSZ)))
        assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

/*
** test_remap_3()
**
**     Map two regions so that they are contiguous. Unmap trailing porition
**     of combined regions.
**
*/
void test_remap_4()
{
    oe_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    assert(_init_mman(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    oe_page_t* ptr1;
    if (!(ptr1 = (oe_page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Map 4 pages: [0|1|2|3] */
    oe_page_t* ptr2;
    if (!(ptr2 = (oe_page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    assert(ptr2 + 4 == ptr1);

    /* Unmap [4|5|6|7] */
    assert(_mman_unmap(&h, ptr1, 4 * PGSZ) == 0);

    oe_page_t* ptr3 = ptr2 + 2;

    /* Expand region: [2|3] */
    if (!(ptr3 = (oe_page_t*)_mman_remap(&h, ptr3, 2 * PGSZ, 4 * PGSZ)))
        assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
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
        p[i] = n % 251;
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
    oe_mman_t h;
    const size_t heap_size = 64 * 1024 * 1024;

    assert(_init_mman(&h, heap_size) == 0);

    static elem_t elem[1024];
    const size_t N = sizeof(elem) / sizeof(elem[0]);
    // const size_t M = 20000;
    const size_t M = 1000;

    for (size_t i = 0; i < M; i++)
    {
        size_t r = (size_t)rand() % N;

        if (elem[r].addr)
        {
            assert(_check_mem(&elem[r]));

            if (rand() % 2)
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

                size_t new_size = (rand() % 16 + 1) * PGSZ;
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
            size_t size = (rand() % 16 + 1) * PGSZ;
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

    assert(oe_mman_is_sane(&h));

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

/*
** test_out_of_memory()
**
**     Loop while mapping memory until all memory is exhausted.
**
*/
void test_out_of_memory()
{
    oe_mman_t h;
    const size_t heap_size = 64 * 1024 * 1024;

    assert(_init_mman(&h, heap_size) == 0);

    /* Use up all the memory */
    while (_mman_mmap_no_err(&h, NULL, 64 * PGSZ))
        ;

    assert(oe_mman_is_sane(&h));

    _merge_coverage(&h);
    _free_mman(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    OE_UNUSED(argc);
    test_mman_1();
    test_mman_2();
    test_mman_3();
    test_mman_4();
    test_mman_5();
    test_mman_6();
    test_remap_1();
    test_remap_2();
    test_remap_3();
    test_remap_4();
    test_mman_randomly();
    test_out_of_memory();
    _check_coverage();
    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
