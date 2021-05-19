#define _GNU_SOURCE
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
#include <myst/spinlock.h>
#include <myst/strings.h>

// the minimum possible size of the mman data (8 pages): one overhead page
// and seven usable pages.
#define MIN_DATA_SIZE (8 * 4096)

#define PROT_SEM 0x8
#define PROT_SAO 0x10

typedef struct page
{
    uint8_t buf[PAGE_SIZE];
} page_t;

typedef struct mman
{
    uint8_t* data;
    size_t size;

    /* overhead vectors */
    uint32_t* pids; /* page pid vector */
    int* fds;       /* file-descriptor vector */
    uint8_t* prots; /* page protection vector */
    uint8_t* bits;  /* page bits */

    /* the index of the lowest non-zero bit */
    size_t first_zero_bit;

    /* the pages */
    page_t* pages; /* page vector */
    size_t npages; /* the number of usable pages (less overhead) */

    myst_spinlock_t lock;
} mman_t;

/* mman state data */
static mman_t _mman;

/* Layout: [pids][fds][prots][bits][pages] */

MYST_INLINE uint64_t _round_up(uint64_t x, uint64_t m)
{
    return (x + m - 1) / m * m;
}

MYST_INLINE bool _valid_start(const void* ptr)
{
    const ptrdiff_t start = (ptrdiff_t)_mman.pages;
    const ptrdiff_t end = (ptrdiff_t)(_mman.pages + _mman.npages - 1);
    return (ptrdiff_t)ptr >= start && (ptrdiff_t)ptr <= end;
}

MYST_INLINE bool _valid_end(const void* ptr)
{
    const ptrdiff_t start = (ptrdiff_t)_mman.pages;
    const ptrdiff_t end = (ptrdiff_t)(_mman.pages + _mman.npages);
    return (ptrdiff_t)ptr >= start && (ptrdiff_t)ptr <= end;
}

size_t myst_mman2_get_usable_size(void)
{
    return _mman.npages * PAGE_SIZE;
}

size_t myst_mman2_count_free_bits(void)
{
    return myst_count_zero_bits(_mman.bits, _mman.npages);
}

size_t myst_mman2_count_used_bits(void)
{
    return myst_count_one_bits(_mman.bits, _mman.npages);
}

int myst_mman2_init(void* data, size_t size)
{
    int ret = 0;
    size_t pids_size;
    size_t fds_size;
    size_t prots_size;
    size_t bits_size;
    size_t overhead_size;

    if (!data || size < MIN_DATA_SIZE || (size % PAGE_SIZE))
        ERAISE(-EINVAL);

    _mman.data = data;
    _mman.size = size;

    /* calculate the overhead size: [pids][fds][prots][bits][page-alignment] */
    {
        size_t npages = size / PAGE_SIZE;
        size_t nbits;

        nbits = _round_up(npages, 8);
        pids_size = nbits * sizeof(uint32_t);
        fds_size = nbits * sizeof(int);
        prots_size = nbits * sizeof(uint8_t);
        bits_size = nbits / 8;
        overhead_size = pids_size + fds_size + prots_size + bits_size;
        overhead_size = _round_up(overhead_size, PAGE_SIZE);
    }

    /* calculate the number of usable pages (less the overhead size) */
    _mman.npages = (size - overhead_size) / PAGE_SIZE;

    /* initialize the vectors: [pids][fds][prots][bits][pages] */
    _mman.pids = (uint32_t*)_mman.data;
    _mman.fds = (int*)(_mman.data + pids_size);
    _mman.prots = (uint8_t*)(_mman.data + pids_size + fds_size);
    _mman.bits = (uint8_t*)(_mman.data + pids_size + fds_size + prots_size);
    _mman.pages = (page_t*)(_mman.data + overhead_size);
    assert(((_mman.npages * PAGE_SIZE) + overhead_size) == size);

    /* clear the overhead pages */
    memset(_mman.data, 0, overhead_size);

done:
    return ret;
}

void myst_mman2_release(void)
{
    memset(&_mman, 0, sizeof(_mman));
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
    bool locked = false;

    if (ptr)
        *ptr = MAP_FAILED;

    if (length == 0)
        ERAISE(-EINVAL);

    if (addr)
        ERAISE(-EINVAL);

    (void)flags;
    (void)fd;
    (void)offset;

    /* round length up to the page size */
    length = _round_up(length, PAGE_SIZE);

    /* calculate the required number of pages */
    size_t rpages = length / PAGE_SIZE;

    /* obtain lock */
    myst_spin_lock(&_mman.lock);
    locked = true;

    /* search for a big enough sequence of free pages */
    {
        size_t i = _mman.first_zero_bit;
        bool found = false;
        bool first_pass = true;
        uint8_t* bits = _mman.bits;
        const size_t nbits = _mman.npages;

        /* search the bitmap for a sequence of free bits */
        while ((i = myst_skip_one_bits(bits, nbits, i)) < nbits &&
               (i + rpages) <= nbits)
        {
            if (first_pass)
            {
                _mman.first_zero_bit = i;
                first_pass = false;
            }

            size_t r = myst_skip_zero_bits(bits, nbits, i, i + rpages);

            if (r - i == rpages)
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
            const size_t hi = i + rpages;

            /* update the process-id vector */
            myst_memset_u32(&_mman.pids[lo], getpid(), rpages);

            /* update the protections vector */
            memset(&_mman.prots[lo], (uint8_t)prot, rpages);

            /* update the bits vector */
            myst_set_bits(bits, nbits, lo, hi);

            /* release the lock */
            myst_spin_unlock(&_mman.lock);
            locked = false;

            /* set the pointer and zero the memory */
            *ptr = &_mman.pages[lo];
            myst_bzero_u128(*ptr, length / sizeof(__uint128_t));

            goto done;
        }
    }

    ERAISE(-ENOMEM);

done:

    if (locked)
        myst_spin_unlock(&_mman.lock);

    return ret;
}

int myst_mman2_munmap(void* addr, size_t length)
{
    int ret = 0;
    bool locked = false;

    /* address cannot be null and must be aligned on a page boundary */
    if (!addr || ((uint64_t)addr % PAGE_SIZE) || !length)
        ERAISE(-EINVAL);

    /* align length to the page boundary */
    length = _round_up(length, PAGE_SIZE);

    /* obtain lock */
    myst_spin_lock(&_mman.lock);
    locked = true;

    /* calculate the start and end addresses for this range of pages */
    page_t* start = (page_t*)addr;
    page_t* end = (page_t*)((uint8_t*)addr + length);

    /* if the address is out of range */
    if (!_valid_start(start))
        ERAISE(-EINVAL);

    /* if the ending address is out of range */
    if (!_valid_end(end))
        ERAISE(-EINVAL);

    /* find the low and high indices of the range */
    const size_t lo = start - _mman.pages;
    const size_t hi = end - _mman.pages;

    /* find the number of pages */
    size_t n = length / PAGE_SIZE;

    /* update the pids vector */
    memset(&_mman.pids[lo], 0, n * sizeof(uint32_t));

    /* update the fds vector */
    memset((uint32_t*)&_mman.fds[lo], 0, n * sizeof(uint32_t));

    /* update the protection vector */
    memset(&_mman.prots[lo], 0, n);

    /* update the start bit */
    if (lo < _mman.first_zero_bit)
        _mman.first_zero_bit = lo;

    /* update the bits vector */
    myst_clear_bits(_mman.bits, _mman.npages, lo, hi);

#if 0
    printf("unmap: [hi=%zu lo=%zu n=%zu]\n", lo, hi, n);
#endif

done:

    if (locked)
        myst_spin_unlock(&_mman.lock);

    return ret;
}

int myst_mman2_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address,
    void** ptr)
{
    int ret = 0;

    if (ptr)
        *ptr = MAP_FAILED;

    if (!old_address || ((uint64_t)old_address % PAGE_SIZE))
        ERAISE(-EINVAL);

    if (old_size == 0 || old_size % PAGE_SIZE)
        ERAISE(-EINVAL);

    if (new_size == 0 || new_size % PAGE_SIZE)
        ERAISE(-EINVAL);

    /* reject unknown flags */
    if ((flags & ~(MREMAP_FIXED | MREMAP_MAYMOVE)))
        ERAISE(-EINVAL);

    /* ATTN: MREMAP_FIXED and new_address not supported */
    if ((flags & MREMAP_FIXED) || new_address)
        ERAISE(-EINVAL);

    /* calculate the start and end addresses for this range of pages */
    page_t* start = (page_t*)old_address;
    page_t* end = (page_t*)((uint8_t*)old_address + old_size);

    /* if the address is out of range */
    if (!_valid_start(start))
        ERAISE(-EINVAL);

    /* if the ending address is out of range */
    if (!_valid_end(end))
        ERAISE(-EINVAL);

    /* if the mapping is exactly the same size */
    if (new_size == old_size)
    {
        *ptr = old_address;
        goto done;
    }

    /* if shriking, then just unmap the excess pages */
    if (new_size < old_size)
    {
        void* addr = (uint8_t*)old_address + new_size;
        const size_t length = old_size - new_size;

        ECHECK(myst_mman2_munmap(addr, length));
        *ptr = old_address;
        goto done;
    }

    /* the mapping is growing */
    {
        size_t npages = (new_size - old_size) / PAGE_SIZE;
        page_t* new_end = start + npages;
        int prot;
        pid_t pid;

        /* verify that all the pages have consistent permissions */
        {
            const size_t lo = start - _mman.pages;
            const size_t hi = end - _mman.pages;
            prot = _mman.prots[lo];

            for (size_t i = lo + 1; i < hi; i++)
            {
                if (_mman.prots[i] != prot)
                    ERAISE(-EPERM);
            }
        }

        /* verify that all the pages have consistent pids */
        {
            const size_t lo = start - _mman.pages;
            const size_t hi = end - _mman.pages;
            pid = _mman.pids[lo];

            for (size_t i = lo + 1; i < hi; i++)
            {
                if (_mman.pids[i] != (uint32_t)pid)
                    ERAISE(-EPERM);
            }
        }

        /* fail if the calling process does not own this mapping */
        if (pid != getpid())
            ERAISE(-EPERM);

        /* if the new end is within the mman memory */
        if (_valid_end(new_end))
        {
            /* find the low and high indices of the range */
            const size_t lo = end - _mman.pages;
            const size_t hi = new_end - _mman.pages;
            size_t i;

            /* check whether the excess pages are available */
            for (i = lo; i < hi && myst_test_bit(_mman.bits, i); i++)
                ;

            /* grow mapping in place */
            if (i == hi)
            {
                /* update the pids vector */
                myst_memset_u32(&_mman.pids[lo], pid, npages);

                /* update the protection vector */
                memset(&_mman.prots[lo], prot, npages);

                /* update the bits vector */
                myst_set_bits(_mman.bits, _mman.npages, lo, hi);

                *ptr = old_address;
                goto done;
            }
        }

        /* cannot grow the mapping in place, so move it */
        if ((flags & MREMAP_MAYMOVE))
        {
            void* new;
            int r;

            /* allocate a new mapping */
            ECHECK(myst_mman2_mmap(NULL, new_size, prot, flags, -1, 0, &new));

            /* copy over the old mapping */
            memcpy(new, old_address, old_size);

            /* unmap of old mapping */
            if ((r = myst_mman2_munmap(old_address, old_size)) != 0)
            {
                myst_mman2_munmap(new, new_size);
                ERAISE(-r);
            }

            *ptr = new;
            goto done;
        }
    }

done:
    return ret;
}

int myst_mman2_mprotect(void* addr, size_t len, int prot)
{
    int ret = 0;
    const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    const int mask = rwx | PROT_SEM | PROT_SAO | PROT_GROWSUP;

    /* address must be non-null and aligned on a page boundary */
    if (!addr || ((ptrdiff_t)addr % PAGE_SIZE))
        ERAISE(-EINVAL);

    /* if length is zero, succeed */
    if ((len = _round_up(len, PAGE_SIZE)) == 0)
        goto done;

    /* reject unknown protection flags */
    if (prot & ~mask)
        ERAISE(-EINVAL);

    /* discard unsupported flags */
    prot &= rwx;

    /* calculate the start and end addresses for this mapping */
    page_t* start = (page_t*)addr;
    page_t* end = (page_t*)((uint8_t*)addr + len);

    /* if the address is out of range */
    if (!_valid_start(start))
        ERAISE(-EINVAL);

    /* if the ending address is out of range */
    if (!_valid_end(end))
        ERAISE(-EINVAL);

    /* find the low and high indices of the range */
    const size_t lo = start - _mman.pages;
    const size_t hi = end - _mman.pages;

    /* verify that all pages in this range are actually mapped */
    {
        size_t i;

        for (i = lo; i < hi && myst_test_bit(_mman.bits, i); i++)
            ;

        if (i != hi)
            ERAISE(-ENOMEM);
    }

    /* set the permissions */
    size_t count = end - start;
    memset(&_mman.prots[lo], prot, count);

done:
    return ret;
}

/* get the permissions for the given page */
int myst_mman2_mprotect_stat(void* addr)
{
    int ret = 0;

    /* address must be non-null and aligned on a page boundary */
    if (!addr || ((ptrdiff_t)addr % PAGE_SIZE))
        ERAISE(-EINVAL);

    /* calculate the start addresses for this mapped page */
    page_t* page = (page_t*)addr;

    /* if the address is out of range */
    if (!_valid_start(page))
        ERAISE(-EINVAL);

    /* set the permissions */
    const size_t index = page - _mman.pages;
    ret = _mman.prots[index];

done:
    return ret;
}
