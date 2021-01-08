// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
**==============================================================================
**
** OVERVIEW:
** =========
**
** This file implements the following operations over a flat memory space,
** called a heap.
**
**     BRK   - changes the 'break value' of the memory region
**     SBRK  - reserves a chunk of memory
**     MMAP  - reserves an area of memory
**     MREMAP - expands or shrinks a memory area obtained with MAP
**     MUNMAP - releases a memory area obtained with MAP
**
** The memory space has the following layout.
**
**     <---VADs---><---BREAK---><--UNASSIGNED--><---------MAPPED---------->
**     [..................................................................]
**     ^           ^            ^               ^                         ^
**    BASE       START         BRK             MAP                       END
**
** The memory space is partitioned into four sections:
**
**     VADs       - VADs or virtual address descriptors: (BASE, START)
**     BREAK      - Managed by the BRK and SBRK: [START, BRK)
**     UNASSIGNED - Unassigned memory: [BRK, MAP)
**     MAPPED     - Manged by the MAP, REMAP, and UNMAP: [MAP, END)
**
** The following diagram depicts the values of BASE, START, BRK, MAP, and
** END for a freshly initialized memory space.
**
**     <---VADs---><---------------UNASSIGNED----------------------------->
**     [..................................................................]
**     ^           ^                                                      ^
**    BASE       START                                                   END
**                 ^                                                      ^
**                BRK                                                    MAP
**
** The BREAK section expands by increasing the BRK value. The MAPPED section
** expands by decreasing the MAP value. The BRK and MAP value grow towards
** one another until all unassigned memory is exhausted.
**
** A VAD (virtual address descriptor) is a structure that defines a memory
** region obtained with the MMAP or MREMAP operations. A VAD keeps track
** of the following information about a memory region.
**
**     - The next VAD on the linked list (see description below).
**     - The previous VAD on the linked list (see description below).
**     - The starting address of the memory region.
**     - The size of the memory region.
**     - Memory projection flags (must be read-write for SGX1).
**     - Memory mapping flags (must be anonymous-private for SGX1).
**
** VADs are either assigned or free. Assigned VADs are kept on a doubly-linked
** list, sorted by starting address. When VADs are freed (by the UNMAP
** operation), they are inserted to the singly-linked VAD free list.
**
** PERFORMANCE:
** ============
**
** The current implementation organizes VADs onto a simple linear linked list.
** The time complexities of the related operations (MAP, REMAP, and UNMAP) are
** all O(N), where N is the number of VADs in the linked list.
**
** In the worst case, N is the maximum number of pages, where a memory region
** is assigned for every available page. For a 128 MB memory space, N is less
** than 32,768.
**
** The MUSL memory allocator (malloc, realloc, calloc, free) uses both
**
**     - BREAK memory -- for allocations less than 56 pages
**     - MAPPED memory -- for allocates greater or equal to 57 pages
**
** In this context, the time complexities of the mapping operations fall to
** O(M), where M is:
**
**     NUM_PAGES = 32,768 pages
**     SMALLEST_ALLOCATION = 57 pages
**     M = NUM_PAGES / SMALLEST_ALLOCATION
**     M = 574
**
** M will even be smaller when the VADs and BREAK regions are subtracted from
** NUM_PAGES. A rough estimates puts the time complexity for the mapping
** operations at about O(M), where M == 400.
**
** OPTIMIZATION:
** =============
**
** To optimize performance, one might consider organizing the active VADs into
** a balanced binary tree variant (AVL or red-black). Two operations must be
** accounted for.
**
**     - Address lookup -- lookup the VAD that contains the given address
**     - Gap lookup -- find a gap greater than a given size
**
** For address lookup a simple AVL tree will suffice such that the key is the
** starting address of the VAD. The lookup function should check to see if the
** address falls within the address range given by the VAD. Address lookup will
** be O(log 2 N).
**
** Gap lookup is more complicated. The AVL tree could be extended so that each
** node in the tree (that is each VAD) contains the maximum gap size of the
** subtree for which it is a root. The lookup function simply looks for any
** gap that is large enough. An alternative is to look for the best fit, but
** this is not strictly necessary. Gap lookup will be O(log 2 N).
**
**==============================================================================
*/

#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <myst/defs.h>
#include <myst/fsgs.h>
#include <myst/mman.h>
#include <myst/round.h>
#include <myst/spinlock.h>
#include <myst/strings.h>

/*
**==============================================================================
**
** Local utility functions:
**
**==============================================================================
*/

/* Get the end address of a VAD */
static uintptr_t _end(myst_vad_t* vad)
{
    return vad->addr + vad->size;
}

/* Get the size of the gap to the right of this VAD */
static size_t _get_right_gap(myst_mman_t* mman, myst_vad_t* vad)
{
    if (vad->next)
    {
        /* Get size of gap between this VAD and next one */
        return vad->next->addr - _end(vad);
    }
    else
    {
        /* Get size of gap between this VAD and the end of the heap */
        return mman->end - _end(vad);
    }
}

/*
**==============================================================================
**
** _FreeList functions
**
**==============================================================================
*/

/* Get a VAD from the free list */
static myst_vad_t* _free_list_get(myst_mman_t* mman)
{
    myst_vad_t* vad = NULL;

    /* First try the free list */
    if (mman->free_vads)
    {
        vad = mman->free_vads;
        mman->free_vads = vad->next;
        goto done;
    }

    /* Now try the myst_vad_t array */
    if (mman->next_vad != mman->end_vad)
    {
        vad = mman->next_vad++;
        goto done;
    }

done:
    return vad;
}

/* Return a free myst_vad_t to the free list */
static void _free_list_put(myst_mman_t* mman, myst_vad_t* vad)
{
    /* Clear the VAD */
    vad->addr = 0;
    vad->size = 0;
    vad->prot = 0;
    vad->flags = 0;

    /* Insert into singly-linked free list as first element */
    vad->next = mman->free_vads;
    mman->free_vads = vad;
}

/*
**==============================================================================
**
** _List functions
**
**==============================================================================
*/

/* Insert VAD after PREV in the linked list */
static void _list_insert_after(
    myst_mman_t* mman,
    myst_vad_t* prev,
    myst_vad_t* vad)
{
    if (prev)
    {
        vad->prev = prev;
        vad->next = prev->next;

        if (prev->next)
            prev->next->prev = vad;

        prev->next = vad;
    }
    else
    {
        vad->prev = NULL;
        vad->next = mman->vad_list;

        if (mman->vad_list)
            mman->vad_list->prev = vad;

        mman->vad_list = vad;
    }
}

/* Remove VAD from the doubly-linked list */
static void _list_remove(myst_mman_t* mman, myst_vad_t* vad)
{
    /* Remove from doubly-linked list */
    if (vad == mman->vad_list)
    {
        mman->vad_list = vad->next;

        if (vad->next)
            vad->next->prev = NULL;
    }
    else
    {
        if (vad->prev)
            vad->prev->next = vad->next;

        if (vad->next)
            vad->next->prev = vad->prev;
    }
}

/* Find a VAD that contains the given address */
static myst_vad_t* _list_find(myst_mman_t* mman, uintptr_t addr)
{
    myst_vad_t* p;

    for (p = mman->vad_list; p; p = p->next)
    {
        if (addr >= p->addr && addr < _end(p))
            return p;
    }

    /* Not found */
    return NULL;
}

/*
**==============================================================================
**
** mman helper functions
**
**==============================================================================
*/

/* Lock the mman and set the 'locked' parameter to true */
MYST_INLINE void _mman_lock(myst_mman_t* mman, bool* locked)
{
    myst_spin_lock(&mman->lock);
    *locked = true;
}

/* Unlock the mman and set the 'locked' parameter to false */
MYST_INLINE void _mman_unlock(myst_mman_t* mman, bool* locked)
{
    if (*locked)
    {
        myst_spin_unlock(&mman->lock);
        *locked = false;
    }
}

/* Clear the mman error message */
static void _mman_clear_err(myst_mman_t* mman)
{
    if (mman)
        mman->err[0] = '\0';
}

/* Set the mman error message */
static void _mman_set_err(myst_mman_t* mman, const char* str)
{
    if (mman && str)
        myst_strlcpy(mman->err, str, sizeof(mman->err));
}

/* Inline Helper function to check mman sanity (if enable) */
static bool _mman_is_sane(myst_mman_t* mman)
{
    if (mman->sanity)
        return myst_mman_is_sane(mman);

    return true;
}

/* Allocate and initialize a new VAD */
static myst_vad_t* _mman_new_vad(
    myst_mman_t* mman,
    uintptr_t addr,
    size_t size,
    int prot,
    int flags)
{
    myst_vad_t* vad = NULL;

    if (!(vad = _free_list_get(mman)))
        goto done;

    vad->addr = addr;
    vad->size = (uint32_t)size;
    vad->prot = (uint16_t)prot;
    vad->flags = (uint16_t)flags;

done:
    return vad;
}

/* Synchronize the MAP value to the address of the first list element */
static void _mman_sync_top(myst_mman_t* mman)
{
    if (mman->vad_list)
        mman->map = mman->vad_list->addr;
    else
        mman->map = mman->end;
}

/*
** Search for a gap (greater than or equal to SIZE) in the VAD list. Set
** LEFT to the leftward neighboring VAD (if any). Set RIGHT to the rightward
** neighboring VAD (if any). Return a pointer to the start of that gap.
**
**                     +----+  +--------+
**                     |    |  |        |
**                     |    v  |        v
**     [........MMMMMMMM....MMMM........MMMMMMMMMMMM........]
**              ^                       ^                   ^
**             HEAD                    TAIL                END
**              ^
**             MAP
**
** Search for gaps in the following order:
**     (1) Between HEAD and TAIL
**     (2) Between TAIL and END
**
** Note: one of the following conditions always holds:
**     (1) MAP == HEAD
**     (2) MAP == END
**
*/
static uintptr_t _mman_find_gap(
    myst_mman_t* mman,
    size_t size,
    myst_vad_t** left,
    myst_vad_t** right)
{
    uintptr_t addr = 0;

    *left = NULL;
    *right = NULL;

    if (!_mman_is_sane(mman))
        goto done;

    /* Look for a gap in the VAD list */
    {
        myst_vad_t* p;

        /* Search for gaps between HEAD and TAIL */
        for (p = mman->vad_list; p; p = p->next)
        {
            size_t gap = _get_right_gap(mman, p);

            if (gap >= size)
            {
                *left = p;
                *right = p->next;

                addr = _end(p);
                goto done;
            }
        }
    }

    /* No gaps in linked list so obtain memory from mapped memory area */
    {
        uintptr_t start = mman->map - size;

        /* If memory was exceeded (overrun of break value) */
        if (!(mman->brk <= start))
        {
            goto done;
        }

        if (mman->vad_list)
            *right = mman->vad_list;

        addr = start;
        goto done;
    }

done:
    return addr;
}

static int _munmap(myst_mman_t* mman, void* addr, size_t length)
{
    int ret = -1;
    myst_vad_t* vad = NULL;

    _mman_clear_err(mman);

    /* Reject invaid parameters */
    if (!mman || mman->magic != MYST_MMAN_MAGIC || !addr || !length)
    {
        _mman_set_err(mman, "bad parameter");
        ret = -EINVAL;
        goto done;
    }

    if (!_mman_is_sane(mman))
    {
        _mman_set_err(mman, "bad mman parameter");
        ret = -EINVAL;
        goto done;
    }

    /* ADDRESS must be aligned on a page boundary */
    if ((uintptr_t)addr % PAGE_SIZE)
    {
        _mman_set_err(mman, "bad addr parameter");
        ret = -EINVAL;
        goto done;
    }

    /* Align LENGTH to a multiple of the page size */
    if (length % PAGE_SIZE)
    {
        if (myst_round_up(length, PAGE_SIZE, &length) != 0)
        {
            _mman_set_err(mman, "rounding error: length");
            ret = -EINVAL;
            goto done;
        }
    }

    /* Set start and end pointers for this area */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = (uintptr_t)addr + length;

    /* Find the VAD that contains this address */
    if (!(vad = _list_find(mman, start)))
    {
        _mman_set_err(mman, "address not found");
        ret = -EINVAL;
        goto done;
    }

    /* Fail if this VAD does not contain the end address */
    if (end > _end(vad))
    {
        _mman_set_err(mman, "illegal range");
        ret = -EINVAL;
        goto done;
    }

    /* If the unapping does not cover the entire area given by the VAD, handle
     * the excess portions. There are 4 cases below, where u's represent
     * the portion being unmapped.
     *
     *     Case1: [uuuuuuuuuuuuuuuu]
     *     Case2: [uuuu............]
     *     Case3: [............uuuu]
     *     Case4: [....uuuu........]
     */
    if (vad->addr == start && _end(vad) == end)
    {
        /* Case1: [uuuuuuuuuuuuuuuu] */

        _list_remove(mman, vad);
        _mman_sync_top(mman);
        _free_list_put(mman, vad);
    }
    else if (vad->addr == start)
    {
        /* Case2: [uuuu............] */

        vad->addr += length;
        vad->size -= (uint32_t)length;
        _mman_sync_top(mman);
    }
    else if (_end(vad) == end)
    {
        /* Case3: [............uuuu] */

        vad->size -= (uint32_t)length;
    }
    else
    {
        /* Case4: [....uuuu........] */

        size_t vad_end = _end(vad);

        /* Adjust the left portion */
        vad->size = (uint32_t)(start - vad->addr);

        myst_vad_t* right;

        /* Create VAD for the excess right portion */
        if (!(right = _mman_new_vad(
                  mman, end, vad_end - end, vad->prot, vad->flags)))
        {
            _mman_set_err(mman, "out of VADs");
            ret = -EINVAL;
            goto done;
        }

        _list_insert_after(mman, vad, right);
        _mman_sync_top(mman);
    }

    /* If scrubbing is enabled, then scrub the unmapped memory */
    if (mman->scrub)
        memset(addr, 0xDD, length);

    if (!_mman_is_sane(mman))
    {
        ret = -EINVAL;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static int _mmap(
    myst_mman_t* mman,
    void* addr,
    size_t length,
    int prot,
    int flags,
    void** ptr_out)
{
    int ret = 0;
    uintptr_t start = 0;

    if (ptr_out)
        *ptr_out = NULL;

    _mman_clear_err(mman);

    /* Check for valid mman parameter */
    if (!mman || mman->magic != MYST_MMAN_MAGIC || !ptr_out)
    {
        _mman_set_err(mman, "bad mman parameter");
        ret = -EINVAL;
        goto done;
    }

    if (!_mman_is_sane(mman))
        goto done;

    /* ADDR must be page aligned */
    if (addr && (uintptr_t)addr % PAGE_SIZE)
    {
        _mman_set_err(mman, "bad addr parameter");
        ret = -EINVAL;
        goto done;
    }

    /* LENGTH must be non-zero */
    if (length == 0)
    {
        _mman_set_err(mman, "bad length parameter");
        ret = -EINVAL;
        goto done;
    }

    /* Ignore protection for SGX-1 */
#if 0
    {
        if (!(prot & MYST_PROT_READ))
        {
            _mman_set_err(mman, "bad prot parameter: need MYST_PROT_READ");
            ret = -EINVAL;
            goto done;
        }

        if (!(prot & MYST_PROT_WRITE))
        {
            _mman_set_err(mman, "bad prot parameter: need MYST_PROT_WRITE");
            ret = -EINVAL;
            goto done;
        }

        if (prot & MYST_PROT_EXEC)
        {
            _mman_set_err(mman, "bad prot parameter: remove MYST_PROT_EXEC");
            ret = -EINVAL;
            goto done;
        }
    }
#endif

    /* FLAGS must be (MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE) */
    {
        if (!(flags & MYST_MAP_ANONYMOUS))
        {
            _mman_set_err(
                mman, "bad flags parameter: need MYST_MAP_ANONYMOUS");
            ret = -EINVAL;
            goto done;
        }

        if (!(flags & MYST_MAP_PRIVATE))
        {
            _mman_set_err(mman, "bad flags parameter: need MYST_MAP_PRIVATE");
            ret = -EINVAL;
            goto done;
        }

        if (flags & MYST_MAP_SHARED)
        {
            _mman_set_err(mman, "bad flags parameter: remove MYST_MAP_SHARED");
            ret = -EINVAL;
            goto done;
        }

        if (flags & MYST_MAP_FIXED)
        {
            _mman_set_err(mman, "bad flags parameter: remove MYST_MAP_FIXED");
            ret = -EINVAL;
            goto done;
        }
    }

    /* Round LENGTH to multiple of page size */
    if (myst_round_up(length, PAGE_SIZE, &length) != 0)
    {
        _mman_set_err(mman, "rounding error: length");
        ret = -EINVAL;
        goto done;
    }

    if (addr)
    {
        myst_vad_t* vad;
        uintptr_t start = (uintptr_t)addr;
        uintptr_t end = (uintptr_t)addr + length;

        /* Fail if [addr:length] is not already mapped */
        if (!(vad = _list_find(mman, start)) || end > _end(vad))
        {
            _mman_set_err(
                mman,
                "bad addr parameter: "
                "must be null or part of an existing mapping");
            ret = -EINVAL;
            goto done;
        }

        *ptr_out = addr;
        goto done;
    }
    else
    {
        myst_vad_t* left;
        myst_vad_t* right;

        /* Find a gap that is big enough */
        if (!(start = _mman_find_gap(mman, length, &left, &right)))
        {
            _mman_set_err(mman, "out of memory");
            ret = -ENOMEM;
            goto done;
        }

        if (left && _end(left) == start)
        {
            /* Coalesce with LEFT neighbor */

            left->size += (uint32_t)length;

            /* Coalesce with RIGHT neighbor (and release right neighbor) */
            if (right && (start + length == right->addr))
            {
                _list_remove(mman, right);
                left->size += right->size;
                _free_list_put(mman, right);
            }
        }
        else if (right && (start + length == right->addr))
        {
            /* Coalesce with RIGHT neighbor */

            right->addr = start;
            right->size += (uint32_t)length;
            _mman_sync_top(mman);
        }
        else
        {
            myst_vad_t* vad;

            /* Create a new VAD and insert it into the list */

            if (!(vad = _mman_new_vad(mman, start, length, prot, flags)))
            {
                _mman_set_err(mman, "unexpected: list insert failed");
                ret = -EINVAL;
                goto done;
            }

            _list_insert_after(mman, left, vad);
            _mman_sync_top(mman);
        }
    }

    if (!_mman_is_sane(mman))
        goto done;

    *ptr_out = (void*)start;

done:

    /* Zero-fill mapped memory */
    if (ptr_out && *ptr_out)
        memset(*ptr_out, 0, length);

    return ret;
}

/*
**==============================================================================
**
** Public interface
**
**==============================================================================
*/

/*
**
** myst_mman_init()
**
**     Initialize a mman structure by setting the 'base' and 'size' and other
**     internal state variables. Note that the caller must obtain a lock if
**     one is needed.
**
** Parameters:
**     [IN] mman - mman structure to be initialized.
**     [IN] base - base address of the heap (must be must be page aligned).
**     [IN] size - size of the heap in bytes (must be multiple of page size).
**
** Returns:
**     0 if successful.
**
*/
int myst_mman_init(myst_mman_t* mman, uintptr_t base, size_t size)
{
    int ret = 0;

    _mman_clear_err(mman);

    /* Check for invalid parameters */
    if (!mman || !base || !size)
    {
        _mman_set_err(mman, "bad parameter");
        ret = -EINVAL;
        goto done;
    }

    /* BASE must be aligned on a page boundary */
    if (base % PAGE_SIZE)
    {
        _mman_set_err(mman, "bad base parameter");
        ret = -EINVAL;
        goto done;
    }

    /* SIZE must be a mulitple of the page size */
    if (size % PAGE_SIZE)
    {
        _mman_set_err(mman, "bad size parameter");
        ret = -EINVAL;
        goto done;
    }

    /* Clear the heap object */
    memset(mman, 0, sizeof(myst_mman_t));

    /* Calculate the total number of pages */
    size_t num_pages = size / PAGE_SIZE;

    /* Save the base of the heap */
    mman->base = base;

    /* Save the size of the heap */
    mman->size = size;

    /* Set the start of the heap area, which follows the VADs array */
    mman->start = base + (num_pages * sizeof(myst_vad_t));

    /* Round start up to next page multiple */
    if (myst_round_up(mman->start, PAGE_SIZE, &mman->start) != 0)
    {
        _mman_set_err(mman, "rounding error: mman->start");
        ret = -EINVAL;
        goto done;
    }

    /* Set the end of the heap area */
    mman->end = base + size;

    /* Set the top of the break memory (grows positively) */
    mman->brk = mman->start;

    /* Set the top of the mapped memory (grows negativey) */
    mman->map = mman->end;

    /* Set pointer to the next available entry in the myst_vad_t array */
    mman->next_vad = (myst_vad_t*)base;

    /* Set pointer to the end address of the myst_vad_t array */
    mman->end_vad = (myst_vad_t*)mman->start;

    /* Set the free myst_vad_t list to null */
    mman->free_vads = NULL;

    /* Set the myst_vad_t linked list to null */
    mman->vad_list = NULL;

    /* Sanity checks are disabled by default */
    mman->sanity = false;

    /* Set the magic number */
    mman->magic = MYST_MMAN_MAGIC;

    /* Finally, set initialized to true */
    mman->initialized = 1;

    /* Check sanity of mman */
    if (!_mman_is_sane(mman))
    {
        ret = -EINVAL;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

/*
**
** myst_mman_sbrk()
**
**     Allocate space from the BREAK region (between the START and BRK value)
**     This increases the BRK value by at least the increment size (rounding
**     up to multiple of 8).
**
** Parameters:
**     [IN] mman - mman structure
**     [IN] increment - allocate this must space.
**
** Returns:
**     Pointer to allocate memory or NULL if BREAK memory has been exhausted.
**
** Notes:
**     This function is similar to the POSIX sbrk() function.
**
*/
int myst_mman_sbrk(myst_mman_t* mman, ptrdiff_t increment, void** ptr_out)
{
    int ret = 0;
    void* ptr = NULL;
    bool locked = false;

    if (ptr_out)
        *ptr_out = NULL;

    _mman_lock(mman, &locked);

    _mman_clear_err(mman);

    if (!_mman_is_sane(mman) || !ptr_out)
    {
        ret = -EINVAL;
        goto done;
    }

    if (increment == 0)
    {
        /* Return the current break value without changing it */
        ptr = (void*)mman->brk;
    }
    else if ((uintptr_t)increment <= mman->map - mman->brk)
    {
        /* Increment the break value and return the old break value */
        ptr = (void*)mman->brk;
        mman->brk += (uintptr_t)increment;
    }
    else
    {
        _mman_set_err(mman, "out of memory");
        ret = -ENOMEM;
        goto done;
    }

    if (!_mman_is_sane(mman))
        goto done;

    *ptr_out = ptr;

done:
    _mman_unlock(mman, &locked);
    return ret;
}

/*
**
** myst_mman_brk()
**
**     Change the BREAK value (within the BREAK region). Increasing the
**     break value has the effect of allocating memory. Decresing the
**     break value has the effect of releasing memory.
**
** Parameters:
**     [IN] mman - mman structure
**     [IN] addr - set the BREAK value to this address (must reside within
**     the break region (beween START and BREAK value).
**
** Returns:
**     0 if successful.
**
** Notes:
**     This function is similar to the POSIX brk() function.
**
*/
int myst_mman_brk(myst_mman_t* mman, void* addr, void** ptr)
{
    int ret = 0;
    bool locked = false;

    if (*ptr)
        *ptr = NULL;

    _mman_clear_err(mman);

    if (!mman || !ptr)
    {
        ret = -EINVAL;
        goto done;
    }

    _mman_lock(mman, &locked);

    if (addr == NULL)
        goto done;

    /* Fail if requested address is not within the break memory area */
    if ((uintptr_t)addr < mman->start || (uintptr_t)addr >= mman->map)
    {
        _mman_set_err(mman, "address is out of range");
        ret = -ENOMEM;
        goto done;
    }

    /* Set the break value */
    mman->brk = (uintptr_t)addr;

    if (!_mman_is_sane(mman))
    {
        _mman_set_err(mman, "bad mman parameter");
        ret = -ENOMEM;
        goto done;
    }

done:

    /* Always return the break value (even on error) */
    if (mman)
        *ptr = (void*)mman->brk;

    _mman_unlock(mman, &locked);
    return ret;
}

/*
**
** myst_mman_mmap()
**
**     Allocate 'length' bytes from the MAPPED region. The 'length' parameter
**     is rounded to a multiple of the page size.
**
** Parameters:
**     [IN] mman - mman structure
**     [IN] addr - must be null in this implementation
**     [IN] length - length in bytes of the new allocation
**     [IN] prot - must be (MYST_PROT_READ | MYST_PROT_WRITE)
**     [IN] flags - must be (MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE)
**
** Returns:
**     Pointer to newly mapped memory if successful.
**
** Notes:
**     This function is similar to the POSIX mmap() function.
**
** Implementation:
**     This function searches for a gap such that gap >= length. If found,
**     it initializes a new VAD structure and inserts it into the active
**     VAD list.
**
*/
int myst_mman_mmap(
    myst_mman_t* mman,
    void* addr,
    size_t length,
    int prot,
    int flags,
    void** ptr_out)
{
    bool locked = false;

    _mman_lock(mman, &locked);
    int ret = _mmap(mman, addr, length, prot, flags, ptr_out);
    _mman_unlock(mman, &locked);

    return ret;
}

/*
**
** myst_mman_munmap()
**
**     Release a memory mapping obtained with myst_mman_mmap() or
**     myst_mman_mremap().
**
**     Note that partial mappings are supported, in which case a portion of
**     the memory obtained with myst_mman_mmap() or myst_mman_mremap() is
**     released.
**
** Parameters:
**     [IN] mman - mman structure
**     [IN] addr - addresss or memory being released (must be page aligned).
**     [IN] length - length of memory being released (multiple of page size).
**
** Returns:
**     MYST_OK if successful.
**
** Notes:
**     This function is similar to the POSIX munmap() function.
**
** Implementation:
**     This function searches the active VAD list for a VAD that contains
**     the range given by 'addr' and 'length'. If the VAD region is larger
**     than the range being freed, then it is split into smaller VADs. The
**     leftward excess (if any) is split into its own VAD and the rightward
**     excess (if any) is split into its own VAD.
**
*/
int myst_mman_munmap(myst_mman_t* mman, void* addr, size_t length)
{
    bool locked = false;

    _mman_lock(mman, &locked);
    int ret = _munmap(mman, addr, length);
    _mman_unlock(mman, &locked);

    return ret;
}

/*
**
** myst_mman_mremap()
**
**     Remap an existing memory region, either making it bigger or smaller.
**
** Parameters:
**     [IN] mman - mman structure
**     [IN] addr - addresss being remapped (must be multiple of page size)
**     [IN] old_size - original size of the memory mapping
**     [IN] new_size - new size of memory mapping (rounded up to page multiple)
**     [IN] flags - must be MYST_MREMAP_MAYMOVE
**
** Returns:
**     Pointer to new memory region.
**
** Notes:
**     This function is similar to the POSIX mremap() function.
**
** Implementation:
**     This function attempts to keep the memory in place if possible. If
**     not, it moves it to a new location.
**
*/
int myst_mman_mremap(
    myst_mman_t* mman,
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags,
    void** ptr_out)
{
    int ret = 0;
    void* new_addr = NULL;
    myst_vad_t* vad = NULL;
    bool locked = false;

    if (ptr_out)
        *ptr_out = NULL;

    _mman_lock(mman, &locked);

    _mman_clear_err(mman);

    /* Check for valid mman parameter */
    if (!mman || mman->magic != MYST_MMAN_MAGIC || !addr || !ptr_out)
    {
        _mman_set_err(mman, "invalid parameter");
        ret = -EINVAL;
        goto done;
    }

    if (!_mman_is_sane(mman))
        goto done;

    /* ADDR must be page aligned */
    if ((uintptr_t)addr % PAGE_SIZE)
    {
        _mman_set_err(
            mman, "bad addr parameter: must be multiple of page size");
        ret = -EINVAL;
        goto done;
    }

    /* OLD_SIZE must be non-zero */
    if (old_size == 0)
    {
        _mman_set_err(mman, "invalid old_size parameter: must be non-zero");
        ret = -EINVAL;
        goto done;
    }

    /* NEW_SIZE must be non-zero */
    if (new_size == 0)
    {
        _mman_set_err(mman, "invalid old_size parameter: must be non-zero");
        ret = -EINVAL;
        goto done;
    }

    /* FLAGS must be exactly MYST_MREMAP_MAYMOVE) */
    if (flags != MYST_MREMAP_MAYMOVE)
    {
        _mman_set_err(
            mman, "invalid flags parameter: must be MYST_MREMAP_MAYMOVE");
        ret = -EINVAL;
        goto done;
    }

    /* Round OLD_SIZE to multiple of page size */
    if (myst_round_up(old_size, PAGE_SIZE, &old_size) != 0)
    {
        _mman_set_err(mman, "rounding error: old_size");
        ret = -EINVAL;
        goto done;
    }

    /* Round NEW_SIZE to multiple of page size */
    if (myst_round_up(new_size, PAGE_SIZE, &new_size) != 0)
    {
        _mman_set_err(mman, "rounding error: new_size");
        ret = -EINVAL;
        goto done;
    }

    /* Set start and end pointers for this area */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t old_end = (uintptr_t)addr + old_size;
    uintptr_t new_end = (uintptr_t)addr + new_size;

    /* Find the VAD containing START */
    if (!(vad = _list_find(mman, start)))
    {
        _mman_set_err(mman, "invalid addr parameter: mapping not found");
        ret = -ENOMEM;
        goto done;
    }

    /* Verify that the end address is within this VAD */
    if (old_end > _end(vad))
    {
        _mman_set_err(mman, "invalid range");
        ret = -ENOMEM;
        goto done;
    }

    /* If the area is shrinking */
    if (new_size < old_size)
    {
        /* If there are excess bytes on the right of this VAD area */
        if (_end(vad) != old_end)
        {
            myst_vad_t* right;

            /* Create VAD for rightward excess */
            if (!(right = _mman_new_vad(
                      mman,
                      old_end,
                      _end(vad) - old_end,
                      vad->prot,
                      vad->flags)))
            {
                _mman_set_err(mman, "out of VADs");
                ret = -ENOMEM;
                goto done;
            }

            _list_insert_after(mman, vad, right);
            _mman_sync_top(mman);
        }

        vad->size = (uint32_t)(new_end - vad->addr);
        new_addr = addr;

        /* If scrubbing is enabled, scrub the unmapped portion */
        if (mman->scrub)
            memset((void*)new_end, 0xDD, old_size - new_size);
    }
    else if (new_size > old_size)
    {
        /* Calculate difference between new and old size */
        size_t delta = new_size - old_size;

        /* If there is room for this area to grow without moving it */
        if (_end(vad) == old_end && _get_right_gap(mman, vad) >= delta)
        {
            vad->size += (uint32_t)delta;
            memset((void*)(start + old_size), 0, delta);
            new_addr = addr;

            /* If VAD is now contiguous with next one, coalesce them */
            if (vad->next && _end(vad) == vad->next->addr)
            {
                myst_vad_t* next = vad->next;
                vad->size += next->size;
                _list_remove(mman, next);
                _mman_sync_top(mman);
                _free_list_put(mman, next);
            }
        }
        else
        {
            if (_mmap(mman, NULL, new_size, vad->prot, vad->flags, &addr) != 0)
            {
                _mman_set_err(mman, "mapping failed");
                ret = -ENOMEM;
            }

            /* Copy over data from old area */
            memcpy(addr, (void*)start, old_size);

            /* Ummap the old area */
            if (_munmap(mman, (void*)start, old_size) != 0)
            {
                _mman_set_err(mman, "unmapping failed");
                ret = -ENOMEM;
                goto done;
            }

            new_addr = (void*)addr;
        }
    }
    else
    {
        /* Nothing to do since size did not change */
        new_addr = addr;
    }

    if (!_mman_is_sane(mman))
        goto done;

    *ptr_out = new_addr;

done:
    _mman_unlock(mman, &locked);
    return ret;
}

/*
**
** myst_mman_is_sane()
**
**     Debugging function used to check sanity (validity) of a mman structure.
**
** Parameters:
**     [IN] mman - mman structure
**
** Returns:
**     true if mman is sane
**
** Implementation:
**     Checks various contraints such as ranges being correct and VAD list
**     being sorted.
**
*/
bool myst_mman_is_sane(myst_mman_t* mman)
{
    bool result = false;

    _mman_clear_err(mman);

    if (!mman)
    {
        _mman_set_err(mman, "invalid parameter");
        goto done;
    }

    _mman_clear_err(mman);

    /* Check the magic number */
    if (mman->magic != MYST_MMAN_MAGIC)
    {
        _mman_set_err(mman, "bad magic");
        goto done;
    }

    /* Check that the mman is initialized */
    if (!mman->initialized)
    {
        _mman_set_err(mman, "uninitialized");
        goto done;
    }

    /* Check that the start of the mman is strictly less than the end */
    if (!(mman->start < mman->end))
    {
        _mman_set_err(mman, "start not less than end");
        goto done;
    }

    if (mman->size != (mman->end - mman->base))
    {
        _mman_set_err(mman, "invalid size");
        goto done;
    }

    if (!(mman->start <= mman->brk))
    {
        _mman_set_err(mman, "!(mman->start <= mman->brk)");
        goto done;
    }

    if (!(mman->map <= mman->end))
    {
        _mman_set_err(mman, "!(mman->map <= mman->end)");
        goto done;
    }

    if (mman->vad_list)
    {
        if (mman->map != mman->vad_list->addr)
        {
            _mman_set_err(mman, "mman->map != mman->vad_list->addr");
            goto done;
        }
    }
    else
    {
        if (mman->map != mman->end)
        {
            _mman_set_err(mman, "mman->map != mman->end");
            goto done;
        }
    }

    /* Verify that the list is sorted */
    {
        myst_vad_t* p;

        for (p = mman->vad_list; p; p = p->next)
        {
            myst_vad_t* next = p->next;

            if (next)
            {
                if (!(p->addr < next->addr))
                {
                    _mman_set_err(mman, "unordered VAD list (1)");
                    goto done;
                }

                /* No two elements should be contiguous due to coalescense */
                if (_end(p) == next->addr)
                {
                    _mman_set_err(mman, "contiguous VAD list elements");
                    goto done;
                }

                if (!(_end(p) <= next->addr))
                {
                    _mman_set_err(mman, "unordered VAD list (2)");
                    goto done;
                }
            }
        }
    }

    result = true;

done:
    return result;
}

/*
**
** myst_mman_set_sanity()
**
**     Enable live sanity checking on the given mman structure. Once enabled,
**     sanity checking is performed in all mapping functions. Be aware that
**     this slows down the implementation and should be used for debugging
**     and testing only.
**
** Parameters:
**     [IN] mman - mman structure
**     [IN] sanity - true to enable sanity checking; false otherwise.
**
*/
void myst_mman_set_sanity(myst_mman_t* mman, bool sanity)
{
    if (mman)
        mman->sanity = sanity;
}

/* return the total size of the mman region */
int myst_mman_total_size(myst_mman_t* mman, size_t* size)
{
    ssize_t ret = 0;

    if (*size)
        *size = 0;

    if (!mman || !size)
    {
        ret = -EINVAL;
        goto done;
    }

    myst_spin_lock(&mman->lock);
    *size = mman->size;
    myst_spin_unlock(&mman->lock);

done:
    return ret;
}

/* return the amount of free space */
int myst_mman_free_size(myst_mman_t* mman, size_t* size_out)
{
    ssize_t ret = 0;
    size_t size;

    if (*size_out)
        *size_out = 0;

    if (!mman || !size_out)
    {
        ret = -EINVAL;
        goto done;
    }

    myst_spin_lock(&mman->lock);
    {
        /* determine the bytes between the BRK value and MAP value */
        size = mman->map - mman->brk;

        /* determine the total size of all gaps */
        for (myst_vad_t* p = mman->vad_list; p; p = p->next)
            size += _get_right_gap(mman, p);
    }
    myst_spin_unlock(&mman->lock);

    *size_out = size;

done:
    return ret;
}
