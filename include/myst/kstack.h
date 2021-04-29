// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_KSTACK_H
#define _MYST_KSTACK_H

#include <stdint.h>

#include <myst/defs.h>

#define MYST_MAX_KSTACKS 1024
#define MYST_KSTACK_SIZE (64 * 1024)
#define MYST_ENTER_KSTACK_SIZE (128 * 1024)

/* representation of the kernel stack (used for syscalls) */
typedef struct myst_kstack
{
    uint8_t guard[4096]; /* overlaid onto non-accessible memory */
    union {
        struct myst_kstack* next; /* used only when on the free list */
        uint8_t __data[MYST_KSTACK_SIZE - 4096];
    } u;
} myst_kstack_t;

MYST_STATIC_ASSERT(sizeof(myst_kstack_t) == MYST_KSTACK_SIZE);

/* put all the kernel stacks onto the free list */
void myst_init_kstacks(void);

/* get a kernel stack from the free list; time complexity is O(1)  */
myst_kstack_t* myst_get_kstack(void);

/* put a kernel stack onto the free list; time complexity is O(1) */
void myst_put_kstack(myst_kstack_t* kstack);

MYST_INLINE void* myst_kstack_end(myst_kstack_t* kstack)
{
    return (uint8_t*)kstack + sizeof(myst_kstack_t);
}

#endif /* _MYST_KSTACK_H */
