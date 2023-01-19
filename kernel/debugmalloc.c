// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <myst/backtrace.h>
#include <myst/printf.h>
#include <myst/debugmalloc.h>
#include <myst/defs.h>
#include <myst/malloc.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/spinlock.h>

#define BACKTRACE_MAX 16

#define ENABLE_MALLOC_MEMSET
#define ENABLE_FREE_MEMSET

// #define DEBUG_MEMALIGN

/*
**==============================================================================
**
** Debug allocator:
**
**     This allocator checks for the following memory errors.
**
**         (1) Leaked blocks on program exit.
**         (2) Memory overwrites just before/after the block.
**         (3) Assuming blocks are zero filled (fills new blocks with 0xAA).
**         (3) Use of free memory (fills freed blocks with 0xDD).
**
**     This allocator keeps in-use blocks on a linked list. Each block has the
**     following layout.
**
**         [padding] [header] [user-data] [footer]
**
**     The padding is applied by memalign() when the alignment is non-zero.
**
**==============================================================================
*/

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

#define HEADER_MAGIC1 0x185f0447c6f5440f
#define HEADER_MAGIC2 0x56cfbed5df804061
#define FOOTER_MAGIC 0x8bb6dcd8f4724bc7

typedef struct header header_t;

struct header
{
    /* Contains HEADER_MAGIC1 */
    uint64_t magic1;

    /* Headers are kept on a doubly-linked list */
    header_t* next;
    header_t* prev;

    /* The alignment passed to memalign() or zero */
    uint64_t alignment;

    /* Size of user memory */
    size_t size;

    /* Return addresses obtained by myst_backtrace() */
    void* addrs[BACKTRACE_MAX];
    uint64_t num_addrs;

    uint64_t padding;

    /* Contains HEADER_MAGIC2 */
    uint64_t magic2;

    /* User data */
    uint8_t data[];
};

/* Verify that the sizeof(header_t) is a multiple of 16 */
MYST_STATIC_ASSERT(sizeof(header_t) % 16 == 0);

typedef struct footer footer_t;

struct footer
{
    /* Contains FOOTER_MAGIC */
    uint64_t magic;
};

MYST_STATIC_ASSERT(sizeof(footer_t) == sizeof(uint64_t));

MYST_INLINE uint64_t _round_up_to_multiple(uint64_t x, uint64_t m)
{
    return (x + m - 1) / m * m;
}

MYST_INLINE bool _is_ptrsize_multiple(size_t n)
{
    size_t d = n / sizeof(void*);
    size_t r = n % sizeof(void*);
    return (d >= 1 && r == 0);
}

MYST_INLINE bool _is_pow2(size_t n)
{
    return (n != 0) && ((n & (n - 1)) == 0);
}

/* Get a pointer to the header from the user data */
MYST_INLINE header_t* _get_header(void* ptr)
{
    return (header_t*)((uint8_t*)ptr - sizeof(header_t));
}

/* Get a pointer to the footer from the user data */
MYST_INLINE footer_t* _get_footer(void* ptr)
{
    header_t* header = _get_header(ptr);
    size_t rsize = _round_up_to_multiple(header->size, sizeof(uint64_t));
    return (footer_t*)((uint8_t*)ptr + rsize);
}

/* Use a macro so the function name will not appear in the backtrace */
#define INIT_BLOCK(HEADER, ALIGNMENT, SIZE)                         \
    do                                                              \
    {                                                               \
        HEADER->magic1 = HEADER_MAGIC1;                             \
        HEADER->next = NULL;                                        \
        HEADER->prev = NULL;                                        \
        HEADER->alignment = ALIGNMENT;                              \
        HEADER->size = SIZE;                                        \
        HEADER->num_addrs =                                         \
            (uint64_t)myst_backtrace(HEADER->addrs, BACKTRACE_MAX); \
        HEADER->magic2 = HEADER_MAGIC2;                             \
        _get_footer(HEADER->data)->magic = FOOTER_MAGIC;            \
    } while (0)

/* Assert and abort if magic numbers are wrong */
static void _check_block(header_t* header)
{
    if (header->magic1 != HEADER_MAGIC1)
        myst_panic("_check_block() panic: header magic1");

    if (header->magic2 != HEADER_MAGIC2)
        myst_panic("_check_block() panic: header magic2");

    if (_get_footer(header->data)->magic != FOOTER_MAGIC)
        myst_panic("_check_block() panic: footer magic");
}

/* Calculate the padding size for a block with this aligment */
MYST_INLINE size_t _get_padding_size(size_t alignment)
{
    if (!alignment)
        return 0;

    const size_t header_size = sizeof(header_t);
    return _round_up_to_multiple(header_size, alignment) - header_size;
}

MYST_INLINE void* _get_block_address(void* ptr)
{
    header_t* header = _get_header(ptr);
    const size_t padding_size = _get_padding_size(header->alignment);
    return (uint8_t*)ptr - sizeof(header_t) - padding_size;
}

MYST_INLINE void* _get_block_address_v2(void* ptr)
{
    header_t* header = _get_header(ptr);
    return (uint8_t*)header - header->padding;
}

MYST_INLINE size_t _calculate_block_size(size_t alignment, size_t size)
{
    size_t r = 0;
    r += _get_padding_size(alignment);
    r += sizeof(header_t);
    r += _round_up_to_multiple(size, sizeof(uint64_t));
    r += sizeof(footer_t);

    /* Check for overflow */
    if (r < size)
        return SIZE_MAX;

    return r;
}

MYST_INLINE size_t _get_block_size(void* ptr)
{
    const header_t* header = _get_header(ptr);
    return _calculate_block_size(header->alignment, header->size);
}

/* Doubly-linked list of headers */
typedef struct _list
{
    header_t* head;
    header_t* tail;
} list_t;

static list_t _list = {NULL, NULL};
static myst_spinlock_t _spin = MYST_SPINLOCK_INITIALIZER;

static void _list_insert(list_t* list, header_t* header)
{
    myst_spin_lock(&_spin);
    {
        if (list->head)
        {
            header->prev = NULL;
            header->next = list->head;
            list->head->prev = header;
            list->head = header;
        }
        else
        {
            header->prev = NULL;
            header->next = NULL;
            list->head = header;
            list->tail = header;
        }
    }
    myst_spin_unlock(&_spin);
}

static void _list_remove(list_t* list, header_t* header)
{
    myst_spin_lock(&_spin);
    {
        if (header->next)
            header->next->prev = header->prev;

        if (header->prev)
            header->prev->next = header->next;

        if (header == list->head)
            list->head = header->next;
        else if (header == list->tail)
            list->tail = header->prev;
    }
    myst_spin_unlock(&_spin);
}

MYST_INLINE bool _check_multiply_overflow(size_t x, size_t y)
{
    if (x == 0 || y == 0)
        return false;

    size_t product = x * y;

    if (x == product / y)
        return false;

    return true;
}

static void _malloc_dump(size_t size, void* addrs[], int num_addrs)
{
    myst_eprintf("%lu bytes\n", size);
    myst_dump_backtrace(addrs, num_addrs);
}

static void _dump(void)
{
    list_t* list = &_list;
    bool found = false;
    size_t blocks = 0;
    size_t bytes = 0;

    /* Count bytes allocated and blocks still in use */
    for (header_t* p = list->head; p; p = p->next)
    {
        found = true;
        blocks++;
        bytes += p->size;
    }

    /* if any non-supressed blocks were found */
    if (found)
    {
        myst_eprintf(
            "=== blocks in use: %zu bytes in %zu blocks\n", bytes, blocks);

        for (header_t* p = list->head; p; p = p->next)
            _malloc_dump(p->size, p->addrs, (int)p->num_addrs);

        myst_eprintf("\n");
    }
}

/*
**==============================================================================
**
** Public definitions:
**
**==============================================================================
*/

void* myst_debug_malloc(size_t size)
{
    void* block;
    const size_t block_size = _calculate_block_size(0, size);

    if (!(block = myst_malloc(block_size)))
        return NULL;

        /* fill block with 0xaa (allocated) bytes */
#ifdef ENABLE_MALLOC_MEMSET
    memset(block, 0xAA, block_size);
#endif

    header_t* header = (header_t*)block;
    INIT_BLOCK(header, 0, size);
    _check_block(header);
    _list_insert(&_list, header);

    return header->data;
}

void myst_debug_free(void* ptr)
{
    if (ptr)
    {
        header_t* header = _get_header(ptr);
        _check_block(header);
        _list_remove(&_list, header);

        void* block = _get_block_address(ptr);

        /* sanity cross check for block address */
        if (block != _get_block_address_v2(ptr))
        {
            assert("_get_block_address_v2() failed");
        }

#ifdef DEBUG_MEMALIGN
        printf("free: block=%p header=%p delta=%zu\n",
            block, header, (const uint8_t*)header - (const uint8_t*)block);
#endif

        /* fill block with 0xdd (deallocated) bytes */
#ifdef ENABLE_FREE_MEMSET
        memset(block, 0xDD, _get_block_size(ptr));
#endif

        myst_free(block);
    }
}

void* myst_debug_calloc(size_t nmemb, size_t size)
{
    void* ptr;

    if (_check_multiply_overflow(nmemb, size))
        return NULL;

    const size_t total_size = nmemb * size;

    if (!(ptr = myst_debug_malloc(total_size)))
        return NULL;

    memset(ptr, 0, total_size);

    return ptr;
}

void* myst_debug_realloc(void* ptr, size_t size)
{
    if (ptr)
    {
        header_t* header = _get_header(ptr);
        void* new_ptr;

        _check_block(header);

        /* If the size is the same, just return the pointer */
        if (header->size == size)
            return ptr;

        if (!(new_ptr = myst_debug_malloc(size)))
            return NULL;

        if (size > header->size)
            memcpy(new_ptr, ptr, header->size);
        else
            memcpy(new_ptr, ptr, size);

        myst_debug_free(ptr);

        return new_ptr;
    }
    else
    {
        return myst_debug_malloc(size);
    }
}

int myst_debug_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    const size_t padding_size = _get_padding_size(alignment);
    const size_t block_size = _calculate_block_size(alignment, size);
    void* block = NULL;
    header_t* header = NULL;
    size_t rsize = _round_up_to_multiple(size, sizeof(uint64_t));

    if (memptr)
        *memptr = NULL;

    if (!memptr)
        return EINVAL;

    /*
    ** [padding][header][block][footer]
    ** ^                ^
    ** |                |
    ** X                Y
    **
    ** Note: both X and Y are on the alignment boundary
    */

#ifdef DEBUG_MEMALIGN
    printf("memalign: padding=%zu header=%zu block=%zu footer=%zu\n",
        padding_size, sizeof(header_t), size, sizeof(footer_t));
#endif

    /* the sum of the parts should add up to total block size */
    if (padding_size + sizeof(header_t) + rsize + sizeof(footer_t)
        != block_size)
    {
        return EINVAL;
    }

    /* the data should be aligned on the given boundary */
    if ((padding_size + sizeof(header_t)) % alignment)
        return EINVAL;

    if (!_is_ptrsize_multiple(alignment) || !_is_pow2(alignment))
        return EINVAL;

    if (myst_posix_memalign(&block, alignment, block_size) != 0)
        return ENOMEM;

    header = (header_t*)((uint8_t*)block + padding_size);

    INIT_BLOCK(header, alignment, size);
    _check_block(header);
    _list_insert(&_list, header);
    *memptr = header->data;

    return 0;
}

void* myst_debug_memalign(size_t alignment, size_t size)
{
    void* ptr = NULL;

    // posix_memalign requires alignment to be a multiple of sizeof(void*)
    alignment = _round_up_to_multiple(alignment, sizeof(void*));

    myst_debug_posix_memalign(&ptr, alignment, size);

    return ptr;
}

size_t myst_debug_malloc_usable_size(void* ptr)
{
    if (!ptr)
        return 0;
    return _get_header(ptr)->size;
}

static size_t _debug_malloc_check(bool dump)
{
    list_t* list = &_list;
    size_t count = 0;

    myst_spin_lock(&_spin);
    {
        if (dump)
            _dump();

        for (header_t* p = list->head; p; p = p->next)
            count++;

        if (count)
        {
            for (header_t* p = list->head; p; p = p->next)
                _check_block(p);
        }
    }
    myst_spin_unlock(&_spin);

    return count;
}

size_t myst_debug_malloc_check(void)
{
    return _debug_malloc_check(true);
}

size_t myst_memcheck(void)
{
    return _debug_malloc_check(false);
}
