#include <libos/mman.h>
#include <openenclave/enclave.h>
#include "run_t.h"

#define D(X)

#define PRINTF oe_host_printf

const void* __oe_get_heap_base();
const void* __oe_get_heap_end();
size_t __oe_get_heap_size();

static size_t PGSZ = OE_PAGE_SIZE;

static bool _coverage[LIBOS_MMAN_COVERAGE_N];

int oe_host_printf(const char* fmt, ...);
void* oe_memalign(size_t alignment, size_t size);
void* oe_malloc(size_t size);
void oe_free(void* ptr);

typedef struct _page
{
    uint8_t buf[4096];
} page_t;

static int _rand(void)
{
    extern uint64_t oe_rdrand();
    return (int)(oe_rdrand() % 0x7fffffff);
}

/* Merge heap implementation coverage branches into _coverage[] variable */
static void _merge_coverage(const libos_mman_t* heap)
{
    for (size_t i = 0; i < LIBOS_MMAN_COVERAGE_N; i++)
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
    for (size_t i = 0; i < LIBOS_MMAN_COVERAGE_N; i++)
    {
        if (i == 10)
        {
            /* sometimes test 10 is uncovered due to randomness */
            continue;
        }

        if (!_coverage[i])
        {
            PRINTF("*** uncovered: LIBOS_MMAN_COVERAGE_%zu\n", i);
            oe_assert(0);
        }
        else
        {
            PRINTF("=== passed test (LIBOS_MMAN_COVERAGE_%zu)\n", i);
        }
    }
}

/* Cound the VADs in the VAD list */
size_t _count_vads(const libos_vad_t* list)
{
    const libos_vad_t* p;
    size_t count = 0;

    for (p = list; p; p = p->next)
        count++;

    return count;
}

/* Initialize the heap object */
static int _init_mman(libos_mman_t* heap, size_t size)
{
    void* base;

    /* Allocate aligned pages */
    if (!(base = oe_memalign(OE_PAGE_SIZE, size)))
    {
        PRINTF("memalign() failed: size=%zu\n", size);
        return -1;
    }

    if (libos_mman_init(heap, (uintptr_t)base, size) != OE_OK)
    {
        PRINTF("ERROR: libos_mman_init(): %s\n", heap->err);
        return -1;
    }

    heap->scrub = true;

    libos_mman_set_sanity(heap, true);

    return 0;
}

/* Free the base of the heap */
static void _free_mman(libos_mman_t* heap)
{
    oe_free((void*)heap->base);
}

/* Check that the VAD list is sorted by starting address */
static bool _is_sorted(const libos_vad_t* list)
{
    const libos_vad_t* p;
    const libos_vad_t* prev = NULL;

    for (p = list; p; prev = p, p = p->next)
    {
        if (prev && !(prev->addr < p->addr))
            return false;
    }

    return true;
}

/* Check that there are no gaps between the VADs in the list */
static bool _is_flush(const libos_mman_t* heap, const libos_vad_t* list)
{
    const libos_vad_t* p;
    const libos_vad_t* prev = NULL;

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

/* Helper for calling libos_mman_map() */
static void* _mman_mmap(libos_mman_t* heap, void* addr, size_t length)
{
    int prot = LIBOS_PROT_READ | LIBOS_PROT_WRITE;
    int flags = LIBOS_MAP_ANONYMOUS | LIBOS_MAP_PRIVATE;

    void* result;

    if (libos_mman_map(heap, addr, length, prot, flags, &result) != 0)
    {
        PRINTF("ERROR: libos_mman_map(): %s\n", heap->err);
        oe_assert("libos_mman_map(): failed" == NULL);
    }

    return result;
}

/* Helper for calling libos_mman_map() without printing an error */
static void* _mman_mmap_no_err(libos_mman_t* heap, void* addr, size_t length)
{
    int prot = LIBOS_PROT_READ | LIBOS_PROT_WRITE;
    int flags = LIBOS_MAP_ANONYMOUS | LIBOS_MAP_PRIVATE;

    void* result = NULL;

    if (libos_mman_map(heap, addr, length, prot, flags, &result) != 0)
        return NULL;

    return result;
}

/* Helper for calling libos_mman_mremap() */
static void* _mman_remap(
    libos_mman_t* heap,
    void* addr,
    size_t old_size,
    size_t new_size)
{
    int flags = LIBOS_MREMAP_MAYMOVE;

    void* result = NULL;

    if (libos_mman_mremap(heap, addr, old_size, new_size, flags, &result) != 0)
    {
        PRINTF("ERROR: libos_mman_mremap(): %s\n", heap->err);
        oe_assert(false);
    }

    return result;
}

/* Helper for calling libos_mman_munmap() */
static int _mman_unmap(libos_mman_t* heap, void* address, size_t size)
{
    int rc = (int)libos_mman_munmap(heap, address, size);

    if (rc != 0)
        PRINTF("ERROR: libos_mman_munmap(): %s\n", heap->err);

    return rc;
}

/*
** test_mman_1()
**
**     Test libos_mman_map() and libos_mman_munmap() and check expected state
*between
**     operations. Unmap leaves gaps and then map checks to see if those gaps
**     are filled.
*/
void test_mman_1()
{
    // char buf1[4096];
    //(void)buf1;
    libos_mman_t h;
    // char buf2[4096];
    //(void)buf2;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    oe_assert(_init_mman(&h, size) == 0);

    oe_assert(h.initialized == true);
    oe_assert(h.size == size);
    oe_assert(h.base != 0);
    oe_assert((uintptr_t)h.next_vad == h.base);
    oe_assert(h.end_vad == h.next_vad + npages);
    oe_assert(h.start == (uintptr_t)h.end_vad);
    oe_assert(h.brk == h.start);
    oe_assert(h.map == h.end);
    oe_assert(_is_sorted(h.vad_list));

    void* ptrs[16];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            oe_assert(0);

        m += r;
    }

    oe_assert(h.brk == h.start);
    oe_assert(h.map == h.end - m);
    oe_assert(_is_sorted(h.vad_list));

    for (size_t i = 0; i < n; i++)
    {
        if (_mman_unmap(&h, ptrs[i], (i + 1) * PGSZ) != 0)
            oe_assert(0);
    }

    oe_assert(_is_sorted(h.vad_list));

    /* Allocate N regions */
    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            oe_assert(0);
    }

    oe_assert(_is_sorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (_mman_unmap(&h, ptrs[i], r) != 0)
            oe_assert(0);
    }

    oe_assert(_is_sorted(h.vad_list));
    oe_assert(_count_vads(h.vad_list) == n / 2);
    oe_assert(_count_vads(h.free_vads) == 0);

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            oe_assert(0);
    }

    oe_assert(_is_sorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (_mman_unmap(&h, ptrs[i], r) != 0)
            oe_assert(0);
    }

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            oe_assert(0);
    }

    oe_assert(_is_sorted(h.vad_list));

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_mman_2()
**
**     Test libos_mman_map() and libos_mman_munmap() and check expected state
*between
**     operations. Map several regions and then unmap regions leaving gaps.
**     Map again and see if the new regions were allocated within the expected
**     gaps.
*/
void test_mman_2()
{
    libos_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    oe_assert(_init_mman(&h, size) == 0);

    void* p0;
    void* p1;
    void* p2;
    {
        if (!(p0 = _mman_mmap(&h, NULL, 2 * OE_PAGE_SIZE)))
            oe_assert(0);

        if (!(p1 = _mman_mmap(&h, NULL, 3 * OE_PAGE_SIZE)))
            oe_assert(0);

        if (!(p2 = _mman_mmap(&h, NULL, 4 * OE_PAGE_SIZE)))
            oe_assert(0);
    }

    oe_assert(_is_sorted(h.vad_list));

    void* p0a;
    void* p0b;
    {
        if (_mman_unmap(&h, p0, 2 * OE_PAGE_SIZE) != 0)
            oe_assert(0);

        oe_assert(_is_sorted(h.vad_list));
        oe_assert(!_is_flush(&h, h.vad_list));

        if (!(p0a = _mman_mmap(&h, NULL, OE_PAGE_SIZE)))
            oe_assert(0);
        oe_assert(p0a == p0);

        oe_assert(_is_sorted(h.vad_list));

        if (!(p0b = _mman_mmap(&h, NULL, OE_PAGE_SIZE)))
            oe_assert(0);
        oe_assert(p0b == (uint8_t*)p0 + OE_PAGE_SIZE);

        oe_assert(_is_sorted(h.vad_list));
        oe_assert(_is_flush(&h, h.vad_list));
    }

    void* p2a;
    void* p2b;
    {
        if (_mman_unmap(&h, p2, 4 * OE_PAGE_SIZE) != 0)
            oe_assert(0);

        oe_assert(_is_sorted(h.vad_list));
        oe_assert(_is_flush(&h, h.vad_list));

        if (!(p2a = _mman_mmap(&h, NULL, OE_PAGE_SIZE)))
            oe_assert(0);
        oe_assert(p2a == (uint8_t*)p2 + 3 * OE_PAGE_SIZE);

        if (!(p2b = _mman_mmap(&h, NULL, 3 * OE_PAGE_SIZE)))
            oe_assert(0);
        oe_assert(p2b == p2);

        oe_assert(_is_sorted(h.vad_list));
        oe_assert(_is_flush(&h, h.vad_list));
    }

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    oe_assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            oe_assert(0);

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

    oe_assert(h.brk == h.start);
    oe_assert(h.map == h.end - m);
    oe_assert(_is_sorted(h.vad_list));

    /* This should be illegal since it overruns the end */
    oe_assert(libos_mman_munmap(&h, ptrs[0], 2 * PGSZ) != 0);
    oe_assert(_is_sorted(h.vad_list));
    oe_assert(_is_flush(&h, h.vad_list));

    /* Unmap ptrs[1] and ptrs[0] */
    if (_mman_unmap(&h, ptrs[1], 3 * PGSZ) != 0)
        oe_assert(0);

    oe_assert(_is_sorted(h.vad_list));
    oe_assert(!_is_flush(&h, h.vad_list));

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
        oe_assert(0);

    oe_assert(_is_sorted(h.vad_list));

    /* Map 6 pages to fill the gap created by last unmap */
    if (!_mman_mmap(&h, NULL, 6 * PGSZ))
        oe_assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    oe_assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            oe_assert(0);

        m += r;
    }

    oe_assert(h.brk == h.start);
    oe_assert(h.map == h.end - m);
    oe_assert(_is_sorted(h.vad_list));

    /* This should fail */
    oe_assert(libos_mman_munmap(&h, ptrs[7], 1024 * PGSZ) != 0);

    /* Unmap everything */
    oe_assert(_mman_unmap(&h, ptrs[7], m) == 0);

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    oe_assert(_init_mman(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _mman_mmap(&h, NULL, r)))
            oe_assert(0);

        m += r;
    }

    /* Unmap a region in the middle */
    oe_assert(_mman_unmap(&h, ptrs[4], 5 * PGSZ) == 0);

    /* Unmap everything */
    oe_assert(libos_mman_munmap(&h, ptrs[7], m) != 0);

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;
    size_t i;
    const size_t n = 8;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    oe_assert(_init_mman(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    if (!(ptr = _mman_mmap(&h, NULL, n * PGSZ)))
        oe_assert(0);

    /* Unmap 8 pages, 1 page at a time */
    for (i = 0; i < n; i++)
    {
        void* p = (uint8_t*)ptr + (i * PGSZ);
        oe_assert(_mman_unmap(&h, p, PGSZ) == 0);
    }

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    oe_assert(_init_mman(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    old_size = 8 * PGSZ;
    if (!(ptr = _mman_mmap(&h, NULL, old_size)))
        oe_assert(0);

    oe_assert(_is_sorted(h.vad_list));
    oe_assert(_is_flush(&h, h.vad_list));

    /* Remap region, making it twice as big */
    new_size = 16 * PGSZ;
    if (!(ptr = _mman_remap(&h, ptr, old_size, new_size)))
    {
        oe_assert(0);
    }

    oe_assert(_is_sorted(h.vad_list));
    oe_assert(!_is_flush(&h, h.vad_list));

    /* Remap region, making it four times smaller */
    old_size = new_size;
    new_size = 4 * PGSZ;
    if (!(ptr = _mman_remap(&h, ptr, old_size, new_size)))
        oe_assert(0);

    oe_assert(_is_sorted(h.vad_list));
    oe_assert(!_is_flush(&h, h.vad_list));

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    oe_assert(_init_mman(&h, size) == 0);

    /* Map N pages */
    old_size = 8 * PGSZ;
    void* ptr1;
    if (!(ptr1 = _mman_mmap(&h, NULL, old_size)))
        oe_assert(0);

    /* Map N pages */
    old_size = 8 * PGSZ;
    void* ptr2;
    if (!(ptr2 = _mman_mmap(&h, NULL, old_size)))
        oe_assert(0);

    /* Remap region, making it twice as big */
    new_size = 16 * PGSZ;
    if (!(ptr2 = _mman_remap(&h, ptr2, old_size, new_size)))
        oe_assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    oe_assert(_init_mman(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    page_t* ptr1;
    if (!(ptr1 = (page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        oe_assert(0);

    /* Map 4 pages: [0|1|2|3] */
    page_t* ptr2;
    if (!(ptr2 = (page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        oe_assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    oe_assert(ptr2 + 4 == ptr1);

    /* Set pointer to overlapped region: [3|4] */
    page_t* ptr3 = ptr2 + 3;

    /* Shrink region: [3|4] */
    if (!(ptr3 = (page_t*)_mman_remap(&h, ptr3, 2 * PGSZ, 1 * PGSZ)))
        oe_assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    oe_assert(_init_mman(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    page_t* ptr1;
    if (!(ptr1 = (page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        oe_assert(0);

    /* Map 4 pages: [0|1|2|3] */
    page_t* ptr2;
    if (!(ptr2 = (page_t*)_mman_mmap(&h, NULL, 4 * PGSZ)))
        oe_assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    oe_assert(ptr2 + 4 == ptr1);

    /* Unmap [4|5|6|7] */
    oe_assert(_mman_unmap(&h, ptr1, 4 * PGSZ) == 0);

    page_t* ptr3 = ptr2 + 2;

    /* Expand region: [2|3] */
    if (!(ptr3 = (page_t*)_mman_remap(&h, ptr3, 2 * PGSZ, 4 * PGSZ)))
        oe_assert(0);

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
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
    libos_mman_t h;
    const size_t heap_size = 64 * 1024 * 1024;

    oe_assert(_init_mman(&h, heap_size) == 0);

    static elem_t elem[1024];
    const size_t N = sizeof(elem) / sizeof(elem[0]);
    // const size_t M = 20000;
    const size_t M = 1000;

    for (size_t i = 0; i < M; i++)
    {
        size_t r = (size_t)_rand() % N;

        if (elem[r].addr)
        {
            oe_assert(_check_mem(&elem[r]));

            if (_rand() % 2)
            {
                D(PRINTF(
                      "unmap: addr=%p size=%zu\n", elem[r].addr, elem[r].size);)

                oe_assert(_mman_unmap(&h, elem[r].addr, elem[r].size) == 0);
                elem[r].addr = NULL;
                elem[r].size = 0;
            }
            else
            {
                void* addr = elem[r].addr;
                oe_assert(addr);

                size_t old_size = elem[r].size;
                oe_assert(old_size > 0);

                size_t new_size = (size_t)(_rand() % 16 + 1) * PGSZ;
                oe_assert(new_size > 0);

                D(PRINTF(
                      "remap: addr=%p old_size=%zu new_size=%zu\n",
                      addr,
                      old_size,
                      new_size);)

                addr = _mman_remap(&h, addr, old_size, new_size);
                oe_assert(addr);

                elem[r].addr = addr;
                elem[r].size = new_size;
                _set_mem(&elem[r]);
            }
        }
        else
        {
            size_t size = (size_t)(_rand() % 16 + 1) * PGSZ;
            oe_assert(size > 0);

            void* addr = _mman_mmap(&h, NULL, size);
            oe_assert(addr);

            D(PRINTF("map: addr=%p size=%zu\n", addr, size);)

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
            D(PRINTF("addr=%p size=%zu\n", elem[i].addr, elem[i].size);)
            oe_assert(_check_mem(&elem[i]));
            oe_assert(_mman_unmap(&h, elem[i].addr, elem[i].size) == 0);
        }
    }

    /* Everything should be unmapped */
    oe_assert(h.vad_list == NULL);

    oe_assert(libos_mman_is_sane(&h));

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
}

/*
** test_out_of_memory()
**
**     Loop while mapping memory until all memory is exhausted.
**
*/
void test_out_of_memory()
{
    libos_mman_t h;
    const size_t heap_size = 64 * 1024 * 1024;

    oe_assert(_init_mman(&h, heap_size) == 0);

    /* Use up all the memory */
    while (_mman_mmap_no_err(&h, NULL, 64 * PGSZ))
        ;

    oe_assert(libos_mman_is_sane(&h));

    _merge_coverage(&h);
    _free_mman(&h);
    PRINTF("=== passed test (%s)\n", __FUNCTION__);
}

int run_ecall(void)
{
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

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,         /* ProductID */
    1,         /* SecurityVersion */
    true,      /* Debug */
    16 * 4096, /* NumHeapPages */
    4096,      /* NumStackPages */
    2);        /* NumTCS */
