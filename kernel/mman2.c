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
#define FAST_BITOPS

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
static size_t _first_zero_bit;

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

    return s;
}

#if 0
static uint64_t* _uint64_bzero(uint64_t* s, size_t n)
{
    uint64_t* p = s;

    while (n >= 32)
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
        p[16] = 0;
        p[17] = 0;
        p[18] = 0;
        p[19] = 0;
        p[20] = 0;
        p[21] = 0;
        p[22] = 0;
        p[23] = 0;
        p[24] = 0;
        p[25] = 0;
        p[26] = 0;
        p[27] = 0;
        p[28] = 0;
        p[29] = 0;
        p[30] = 0;
        p[31] = 0;
        p += 32;
        n -= 32;
    }

    /* handle remaining bytes if any */
    while (n--)
        *p++ = 0;

    return s;
}
#endif

/* this is faster than memset */
MYST_UNUSED
static __uint128_t* _uint128_bzero(__uint128_t* s, size_t n)
{
    __uint128_t* p = s;

    while (n >= 32)
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
        p[16] = 0;
        p[17] = 0;
        p[18] = 0;
        p[19] = 0;
        p[20] = 0;
        p[21] = 0;
        p[22] = 0;
        p[23] = 0;
        p[24] = 0;
        p[25] = 0;
        p[26] = 0;
        p[27] = 0;
        p[28] = 0;
        p[29] = 0;
        p[30] = 0;
        p[31] = 0;
        p += 32;
        n -= 32;
    }

    /* handle remaining bytes if any */
    while (n--)
        *p++ = 0;

    return s;
}

MYST_INLINE size_t _min(size_t x, size_t y)
{
    return x < y ? x : y;
}

static size_t _skip_set_bits(size_t i)
{
    if (i == _npages)
        return _npages;

#ifdef FAST_BITOPS

    /* round i to the next multiple of 64 */
    size_t m = (i + 63) / 64 * 64;

    /* if i is not aligned, then process bits up to next 64-bit alignement */
    if (i != m)
    {
        /* skip bits up to next 64-bit alignment */
        while (i < m && myst_test_bit(_bits, i))
            i++;

        if (i == _npages)
            return i;

        if (myst_test_bit(_bits, i) == 0)
            return i;
    }

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
    while (i < n && !myst_test_bit(_bits, i))
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

MYST_INLINE void _set_bits(size_t lo, size_t hi)
{
    size_t i = lo;

#if 0
    size_t n = hi - lo;

    while (n >= 4)
    {
        myst_set_bit(_bits, i);
        myst_set_bit(_bits, i+1);
        myst_set_bit(_bits, i+2);
        myst_set_bit(_bits, i+3);
        i += 4;
        n -= 4;
    }
#endif

    for (; i < hi; i++)
        myst_set_bit(_bits, i);
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
        size_t i = _first_zero_bit;
        bool found = false;
        bool first_pass = true;

        /* search the bitmap for a sequence of free bits */
        while ((i = _skip_set_bits(i)) < _npages && (i + npages) <= _npages)
        {
            if (first_pass)
            {
                _first_zero_bit = i;
                first_pass = false;
            }

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
            _set_bits(lo, hi);

#if 0
            printf("[%zu:%zu]\n", lo, npages);
#endif
            *ptr = &_pages[lo];
            _uint128_bzero(*ptr, length / sizeof(__uint128_t));

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

    /* update the start bit */
    if (lo < _first_zero_bit)
        _first_zero_bit = lo;

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

size_t myst_mman2_count_used_bits(void)
{
    size_t n = 0;

    for (size_t i = 0; i < _npages; i++)
    {
        if (myst_test_bit(_bits, i))
            n++;
    }

    return n;
}
