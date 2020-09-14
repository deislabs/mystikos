// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debugmalloc.h"

#include <libos/defs.h>
#include <libos/round.h>
#include <libos/spinlock.h>

#define BACKTRACE_MAX 64

#define FILLING
#define CLEARING

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

    /* Return addresses obtained by libos_backtrace() */
    void* addrs[BACKTRACE_MAX];
    uint64_t num_addrs;

    /* Padding to make header a multiple of 16 */
    uint64_t padding;

    /* Contains HEADER_MAGIC2 */
    uint64_t magic2;

    /* User data */
    uint8_t data[];
};

static bool _is_pow2(size_t n)
{
    return (n != 0) && ((n & (n - 1)) == 0);
}

static bool _is_ptrsize_multiple(size_t n)
{
    size_t d = n / sizeof(void*);
    size_t r = n % sizeof(void*);
    return (d >= 1 && r == 0);
}

/* Verify that the sizeof(header_t) is a multiple of 16 */
LIBOS_STATIC_ASSERT(sizeof(header_t) % 16 == 0);

typedef struct footer footer_t;

struct footer
{
    /* Contains FOOTER_MAGIC */
    uint64_t magic;
};

LIBOS_STATIC_ASSERT(sizeof(footer_t) == sizeof(uint64_t));

/* Get a pointer to the header from the user data */
LIBOS_INLINE header_t* _get_header(void* ptr)
{
    return (header_t*)((uint8_t*)ptr - sizeof(header_t));
}

/* Get a pointer to the footer from the user data */
LIBOS_INLINE footer_t* _get_footer(void* ptr)
{
    header_t* header = _get_header(ptr);
    size_t rsize = libos_round_up_u64(header->size, sizeof(uint64_t));
    return (footer_t*)((uint8_t*)ptr + rsize);
}

/* Use a macro so the function name will not appear in the backtrace */
#define INIT_BLOCK(HEADER, ALIGNMENT, SIZE)                                    \
    do                                                                         \
    {                                                                          \
        HEADER->magic1 = HEADER_MAGIC1;                                        \
        HEADER->next = NULL;                                                   \
        HEADER->prev = NULL;                                                   \
        HEADER->alignment = ALIGNMENT;                                         \
        HEADER->size = SIZE;                                                   \
        HEADER->num_addrs = (uint64_t)backtrace(HEADER->addrs, BACKTRACE_MAX); \
        HEADER->magic2 = HEADER_MAGIC2;                                        \
        _get_footer(HEADER->data)->magic = FOOTER_MAGIC;                       \
    } while (0)

/* Assert and abort if magic numbers are wrong */
static void _check_block(header_t* header)
{
    if (header->magic1 != HEADER_MAGIC1)
    {
        assert("_check_block() panic" == NULL);
        abort();
    }

    if (header->magic2 != HEADER_MAGIC2)
    {
        assert("_check_block() panic" == NULL);
        abort();
    }

    if (_get_footer(header->data)->magic != FOOTER_MAGIC)
    {
        assert("_check_block() panic" == NULL);
        abort();
    }
}

/* Calculate the padding size for a block with this aligment */
LIBOS_INLINE size_t _get_padding_size(size_t alignment)
{
    if (!alignment)
        return 0;

    const size_t header_size = sizeof(header_t);
    return libos_round_up_u64(header_size, alignment) - header_size;
}

LIBOS_INLINE void* _get_block_address(void* ptr)
{
    header_t* header = _get_header(ptr);
    const size_t padding_size = _get_padding_size(header->alignment);
    return (uint8_t*)ptr - sizeof(header_t) - padding_size;
}

LIBOS_INLINE size_t _calculate_block_size(size_t alignment, size_t size)
{
    size_t r = 0;
    r += _get_padding_size(alignment);
    r += sizeof(header_t);
    r += libos_round_up_u64(size, sizeof(uint64_t));
    r += sizeof(footer_t);

    /* Check for overflow */
    if (r < size)
        return SIZE_MAX;

    return r;
}

LIBOS_INLINE size_t _get_block_size(void* ptr)
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
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

static void _list_insert(list_t* list, header_t* header)
{
    libos_spin_lock(&_lock);
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
    libos_spin_unlock(&_lock);
}

static void _list_remove(list_t* list, header_t* header)
{
    libos_spin_lock(&_lock);
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
    libos_spin_unlock(&_lock);
}

LIBOS_INLINE bool _check_multiply_overflow(size_t x, size_t y)
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
    char** syms = NULL;

    /* Get symbol names for these addresses */
    if (!(syms = backtrace_symbols(addrs, num_addrs)))
        goto done;

    printf("%lu bytes\n", size);

    for (int i = 0; i < num_addrs; i++)
        printf("%s(): %p\n", syms[i], addrs[i]);

    printf("\n");

done:

    if (syms)
        free(syms);
}

static void _dump(bool need_lock)
{
    list_t* list = &_list;

    if (need_lock)
        libos_spin_lock(&_lock);

    {
        size_t blocks = 0;
        size_t bytes = 0;

        /* Count bytes allocated and blocks still in use */
        for (header_t* p = list->head; p; p = p->next)
        {
            blocks++;
            bytes += p->size;
        }

        printf(
            "=== %s(): %zu bytes in %zu blocks\n", __FUNCTION__, bytes, blocks);

        for (header_t* p = list->head; p; p = p->next)
            _malloc_dump(p->size, p->addrs, (int)p->num_addrs);

        printf("\n");
    }

    if (need_lock)
        libos_spin_unlock(&_lock);
}

/*
**==============================================================================
**
** Public definitions:
**
**==============================================================================
*/

void* libos_debug_malloc(size_t size)
{
    void* block;
    const size_t block_size = _calculate_block_size(0, size);

    if (!(block = malloc(block_size)))
        return NULL;

#ifdef FILLING
    /* Fill block with 0xAA (Allocated) bytes */
    memset(block, 0xAA, block_size);
#endif

    header_t* header = (header_t*)block;
    INIT_BLOCK(header, 0, size);
    _check_block(header);
    _list_insert(&_list, header);

    return header->data;
}

void libos_debug_free(void* ptr)
{
    if (ptr)
    {
        header_t* header = _get_header(ptr);
        _check_block(header);
        _list_remove(&_list, header);

        /* Fill the whole block with 0xDD (Deallocated) bytes */
        void* block = _get_block_address(ptr);
        size_t block_size = _get_block_size(ptr);
        (void)block_size;
#ifdef CLEARING
        memset(block, 0xDD, block_size);
#endif

        free(block);
    }
}

void* libos_debug_calloc(size_t nmemb, size_t size)
{
    void* ptr;

    if (_check_multiply_overflow(nmemb, size))
        return NULL;

    const size_t total_size = nmemb * size;

    if (!(ptr = libos_debug_malloc(total_size)))
        return NULL;

    memset(ptr, 0, total_size);

    return ptr;
}

void* libos_debug_realloc(void* ptr, size_t size)
{
    if (ptr)
    {
        header_t* header = _get_header(ptr);
        void* new_ptr;

        _check_block(header);

        /* If the size is the same, just return the pointer */
        if (header->size == size)
            return ptr;

        if (!(new_ptr = libos_debug_malloc(size)))
            return NULL;

        if (size > header->size)
            memcpy(new_ptr, ptr, header->size);
        else
            memcpy(new_ptr, ptr, size);

        libos_debug_free(ptr);

        return new_ptr;
    }
    else
    {
        return libos_debug_malloc(size);
    }
}

void* libos_debug_memalign(size_t alignment, size_t size)
{
    void* ptr = NULL;

    // The only difference between posix_memalign and the obsolete memalign is
    // that posix_memalign requires alignment to be a multiple of sizeof(void*).
    // Adjust the alignment if needed.
    alignment = libos_round_up_u64(alignment, sizeof(void*));

    libos_debug_posix_memalign(&ptr, alignment, size);
    return ptr;
}

int libos_debug_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    const size_t padding_size = _get_padding_size(alignment);
    const size_t block_size = _calculate_block_size(alignment, size);
    void* block = NULL;
    header_t* header = NULL;

    if (!memptr)
        return -EINVAL;

    if (!_is_ptrsize_multiple(alignment) || !_is_pow2(alignment))
        return -EINVAL;

    if (posix_memalign(&block, alignment, block_size) != 0)
        return -ENOMEM;

    header = (header_t*)((uint8_t*)block + padding_size);

    INIT_BLOCK(header, alignment, size);
    _check_block(header);
    _list_insert(&_list, header);
    *memptr = header->data;

    return 0;
}

size_t libos_debug_malloc_usable_size(void* ptr)
{
    if (!ptr)
        return 0;
    return _get_header(ptr)->size;
}

void libos_debug_malloc_dump(void)
{
    _dump(true);
}

size_t libos_debug_malloc_check(void)
{
    list_t* list = &_list;
    size_t count = 0;

    libos_spin_lock(&_lock);
    {
        for (header_t* p = list->head; p; p = p->next)
            count++;

        if (count)
        {
            _dump(false);

            for (header_t* p = list->head; p; p = p->next)
                _check_block(p);
        }
    }
    libos_spin_unlock(&_lock);

    return count;
}
