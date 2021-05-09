#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <myst/bits.h>
#include <myst/eraise.h>
#include <myst/mman2.h>
#include <myst/round.h>

// the minimum possible size of the mman data (8 pages): one overhead page
// and seven usable pages.
#define MIN_DATA_SIZE (8 * 4096)

typedef struct page
{
    uint8_t buf[PAGE_SIZE];
} page_t;

static uint8_t* _data;
static size_t _size;

/* overhead vectors */
static uint32_t* _pids; /* page pid vector */
static uint8_t* _prots; /* page protection vector */
static uint8_t* _bits;  /* page bits */

/* the pages */
static page_t* _pages; /* page vector */
static size_t _npages; /* the number of usable pages (less overhead) */

/* Layout: [pids][prots][bits][pages] */

/* memset for uint32_t strings */
static uint32_t* _uint32_memset(uint32_t* s, uint32_t c, size_t n)
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

    /* handle remaining bytes if any */
    while (n--)
        *p++ = (uint8_t)c;

    return s;
}

#define FAST_BITOPS

MYST_INLINE size_t _min(size_t x, size_t y)
{
    return x < y ? x : y;
}

static size_t _skip_set_bits(size_t i)
{
#ifdef FAST_BITOPS

    /* the number of bits before the next 64-bit alignment */
    size_t m = i % 64;

    /* if i is not aligned, then process bits up to next 64-bit alignement */
    if (m)
    {
        size_t n = _min(i + m, _npages);

        /* skip bits up to next 64-bit alignment */
        while (i < n && myst_test_bit(_bits, i))
            i++;

        if (i == _npages)
            return i;
    }

    /* i should be 64-bit aligned here */
    assert(i % 64 == 0);

    /* skip over 8 bytes at a time */
    {
        size_t r = _npages - i;

        while (r > 64 && *((uint64_t*)&_bits[i / 8]) == 0xffffffffffffffff)
        {
            i += 64;
            r -= 64;
        }
    }

#endif

    /* handle any remaining bits */
    while (i < _npages && myst_test_bit(_bits, i))
        i++;

    return i;
}

static size_t _skip_zero_bits(size_t i, size_t n)
{
    while (i < n && myst_test_bit(_bits, i) == false)
        i++;

    return i;
}

int myst_mman2_init(void* data, size_t size)
{
    int ret = 0;
    size_t pids_size;
    size_t prots_size;
    size_t bits_size;
    size_t overhead_size;

    if (!data || size < MIN_DATA_SIZE || (size % PAGE_SIZE))
        ERAISE(-EINVAL);

    _data = data;
    _size = size;

    /* calculate the overhead size (pids[] prots[] bits[]) */
    {
        size_t npages = size / PAGE_SIZE;
        size_t nbits;

        ECHECK(myst_round_up(npages, 8, &nbits));
        pids_size = nbits * sizeof(uint32_t);
        prots_size = nbits * sizeof(uint8_t);
        bits_size = nbits / 8;
        overhead_size = pids_size + prots_size + bits_size;
        ECHECK(myst_round_up(overhead_size, PAGE_SIZE, &overhead_size));
    }

    /* calculate the number of usable pages (less the overhead size) */
    _npages = (size - overhead_size) / PAGE_SIZE;

    /* initialize the vectors */
    _pids = (uint32_t*)_data;
    _prots = (uint8_t*)(_data + pids_size);
    _bits = (uint8_t*)(_data + pids_size + prots_size);
    _pages = (page_t*)(_data + overhead_size);
    assert(((_npages * PAGE_SIZE) + overhead_size) == size);

    /* clear the overhead pages */
    memset(_data, 0, overhead_size);

#if 0
    printf("pids_size=%zu\n", pids_size);
    printf("prots_size=%zu\n", prots_size);
    printf("bits_size=%zu\n", bits_size);
    printf("overhead_size=%zu\n", overhead_size);
    printf("_npages=%zu\n", _npages);
#endif

done:
    return ret;
}

int myst_mman2_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset,
    void** ptr)
{
    int ret = 0;

    if (ptr)
        *ptr = MAP_FAILED;

    if (length == 0)
        ERAISE(-EINVAL);

    if (addr)
        ERAISE(-EINVAL);

    (void)prot;
    (void)flags;
    (void)fd;
    (void)offset;

    /* round length up to the page size */
    ECHECK(myst_round_up(length, PAGE_SIZE, &length));

    /* calculate the number of required pages */
    size_t npages = length / PAGE_SIZE;

    /* search for a big enough sequence of free pages */
    {
        size_t i = 0;
        bool found = false;

        /* search the bitmap for a sequence of free bits */
        while ((i = _skip_set_bits(i)) < _npages)
        {
            size_t r = _skip_zero_bits(i, i + npages);

            if (r - i == npages)
            {
                found = true;
                break;
            }

            i = r;
        }

        /* if a big enough sequence of pages was found */
        if (found)
        {
            const size_t lo = i;
            const size_t hi = i + npages;

            /* update the pids vector */
            _uint32_memset(&_pids[lo], getpid(), npages);

            /* update the protection vector */
            memset(&_prots[lo], (uint8_t)prot, npages);

            /* update the bits vector */
            for (i = lo; i < hi; i++)
                myst_set_bit(_bits, i);

#if 0
            printf("[%zu:%zu]\n", lo, npages);
#endif
            *ptr = &_pages[lo];
            goto done;
        }
    }

    ERAISE(-ENOMEM);

done:
    return ret;
}

int myst_mman2_munmap(void* addr, size_t length)
{
    int ret = 0;

    /* address cannot be null and must be aligned on a page boundary */
    if (!addr || ((uint64_t)addr % PAGE_SIZE) || !length)
        ERAISE(-EINVAL);

    /* align length to the page boundary */
    ECHECK(myst_round_up(length, PAGE_SIZE, &length));

    /* calculate the start and end addresses for this range of pages */
    page_t* start = (page_t*)addr;
    page_t* end = (page_t*)((uint8_t*)addr + length);

    /* if the address is out of range */
    if (!(start >= _pages && start < (_pages + _npages)))
        ERAISE(-EINVAL);

    /* if the ending address is out of range */
    if (!(end >= _pages && end <= (_pages + _npages)))
        ERAISE(-EINVAL);

    /* find the low and high indices of the range */
    const size_t lo = start - _pages;
    const size_t hi = end - _pages;

    /* find the number of pages */
    size_t n = length / PAGE_SIZE;

    /* update the pids vector */
    _uint32_memset(&_pids[lo], 0, n);

    /* update the protection vector */
    memset(&_prots[lo], 0, n);

    /* update the bits vector */
    for (size_t i = lo; i < hi; i++)
        myst_clear_bit(_bits, i);

#if 0
    printf("unmap: [hi=%zu lo=%zu n=%zu]\n", lo, hi, n);
#endif

done:
    return ret;
}

size_t myst_mman2_get_usable_size(void)
{
    return _npages * PAGE_SIZE;
}

size_t myst_mman2_count_free_bits(void)
{
    size_t n = 0;

    for (size_t i = 0; i < _npages; i++)
    {
        if (!myst_test_bit(_bits, i))
            n++;
    }

    return n;
}
