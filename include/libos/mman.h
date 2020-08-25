// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_INTERNAL_MMAN_H
#define _LIBOS_INTERNAL_MMAN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <libos/spinlock.h>

#define LIBOS_PROT_NONE 0
#define LIBOS_PROT_READ 1
#define LIBOS_PROT_WRITE 2
#define LIBOS_PROT_EXEC 4

#define LIBOS_MAP_SHARED 1
#define LIBOS_MAP_PRIVATE 2
#define LIBOS_MAP_FIXED 16
#define LIBOS_MAP_ANONYMOUS 32

#define LIBOS_MREMAP_MAYMOVE 1

#define LIBOS_MMAN_ERROR_SIZE 256

/* Virtual Address Descriptor */
typedef struct libos_vad
{
    /* Pointer to next libos_vad_t on linked list */
    struct libos_vad* next;

    /* Pointer to previous libos_vad_t on linked list */
    struct libos_vad* prev;

    /* Address of this memory region */
    uintptr_t addr;

    /* Size of this memory region in bytes */
    uint32_t size;

    /* Protection flags for this region LIBOS_PROT_???? */
    uint16_t prot;

    /* Mapping flags for this region: LIBOS_MAP_???? */
    uint16_t flags;
} libos_vad_t;

_Static_assert(sizeof(libos_vad_t) == 32, "");

#define LIBOS_MMAN_MAGIC 0xcc8e1732ebd80b0b

#define LIBOS_MMAN_ERR_SIZE 256

/* Heap Code coverage */
typedef enum _LIBOS_HeapCoverage
{
    LIBOS_MMAN_COVERAGE_0,
    LIBOS_MMAN_COVERAGE_1,
    LIBOS_MMAN_COVERAGE_2,
    LIBOS_MMAN_COVERAGE_3,
    LIBOS_MMAN_COVERAGE_4,
    LIBOS_MMAN_COVERAGE_5,
    LIBOS_MMAN_COVERAGE_6,
    LIBOS_MMAN_COVERAGE_7,
    LIBOS_MMAN_COVERAGE_8,
    LIBOS_MMAN_COVERAGE_9,
    LIBOS_MMAN_COVERAGE_10,
    LIBOS_MMAN_COVERAGE_11,
    LIBOS_MMAN_COVERAGE_12,
    LIBOS_MMAN_COVERAGE_13,
    LIBOS_MMAN_COVERAGE_14,
    LIBOS_MMAN_COVERAGE_15,
    LIBOS_MMAN_COVERAGE_16,
    LIBOS_MMAN_COVERAGE_17,
    LIBOS_MMAN_COVERAGE_18,
    LIBOS_MMAN_COVERAGE_N,
} libos_mman_coverage_t;

/* libos_mman_t data structures and fields */
typedef struct libos_mman
{
    /* Magic number (LIBOS_MMAN_MAGIC) */
    uint64_t magic;

    /* True if libos_mman_init() has been called */
    bool initialized;

    /* Base of heap (aligned on page boundary) */
    uintptr_t base;

    /* Size of heap (a multiple of LIBOS_PAGE_SIZE) */
    size_t size;

    /* Start of heap (immediately aft4er VADs array) */
    uintptr_t start;

    /* End of heap (points to first page after end of heap) */
    uintptr_t end;

    /* Current break value: top of break memory partition (grows positively) */
    uintptr_t brk;

    /* Current map value: top of mapped memory partition (grows negatively) */
    uintptr_t map;

    /* The next available libos_vad_t in the VADs array */
    libos_vad_t* next_vad;

    /* The end of the VADs array */
    libos_vad_t* end_vad;

    /* The libos_vad_t free list (singly linked) */
    libos_vad_t* free_vads;

    /* Linked list of VADs (sorted by address and doubly linked) */
    libos_vad_t* vad_list;

    /* Whether sanity checks are enabled: see LIBOS_HeapEnableSanityChecks() */
    bool sanity;

    /* Whether to scrub memory when it is unmapped (fill with 0xDD) */
    bool scrub;

    /* Heap locking */
    libos_recursive_spinlock_t lock;

    /* Error string */
    char err[LIBOS_MMAN_ERROR_SIZE];

    /* Code coverage array */
    bool coverage[LIBOS_MMAN_COVERAGE_N];

} libos_mman_t;

int libos_mman_init(libos_mman_t* heap, uintptr_t base, size_t size);

int libos_mman_map(
    libos_mman_t* heap,
    void* addr,
    size_t length,
    int prot,
    int flags,
    void** ptr);

int libos_mman_mremap(
    libos_mman_t* heap,
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags,
    void** ptr);

int libos_mman_munmap(libos_mman_t* heap, void* address, size_t size);

void libos_mman_dump(const libos_mman_t* h, bool full);

int libos_mman_sbrk(libos_mman_t* heap, ptrdiff_t increment, void** ptr);

int libos_mman_brk(libos_mman_t* mman, void* addr, void** ptr);

void libos_mman_set_sanity(libos_mman_t* heap, bool sanity);

bool libos_mman_is_sane(libos_mman_t* heap);

#endif /* _LIBOS_INTERNAL_MMAN_H */
