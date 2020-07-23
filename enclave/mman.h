// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OEL_INTERNAL_MMAN_H
#define _OEL_INTERNAL_MMAN_H

#include "types.h"

#define OEL_PROT_NONE 0
#define OEL_PROT_READ 1
#define OEL_PROT_WRITE 2
#define OEL_PROT_EXEC 4

#define OEL_MAP_SHARED 1
#define OEL_MAP_PRIVATE 2
#define OEL_MAP_FIXED 16
#define OEL_MAP_ANONYMOUS 32

#define OEL_MREMAP_MAYMOVE 1

#define OEL_MMAN_ERROR_SIZE 256

/* Virtual Address Descriptor */
typedef struct _oel_vad
{
    /* Pointer to next oel_vad_t on linked list */
    struct _oel_vad* next;

    /* Pointer to previous oel_vad_t on linked list */
    struct _oel_vad* prev;

    /* Address of this memory region */
    uintptr_t addr;

    /* Size of this memory region in bytes */
    uint32_t size;

    /* Protection flags for this region OEL_PROT_???? */
    uint16_t prot;

    /* Mapping flags for this region: OEL_MAP_???? */
    uint16_t flags;
} oel_vad_t;

OE_STATIC_ASSERT(sizeof(oel_vad_t) == 32);

#define OEL_MMAN_MAGIC 0xcc8e1732ebd80b0b

#define OEL_MMAN_ERR_SIZE 256

/* Heap Code coverage */
typedef enum _OEL_HeapCoverage
{
    OEL_MMAN_COVERAGE_0,
    OEL_MMAN_COVERAGE_1,
    OEL_MMAN_COVERAGE_2,
    OEL_MMAN_COVERAGE_3,
    OEL_MMAN_COVERAGE_4,
    OEL_MMAN_COVERAGE_5,
    OEL_MMAN_COVERAGE_6,
    OEL_MMAN_COVERAGE_7,
    OEL_MMAN_COVERAGE_8,
    OEL_MMAN_COVERAGE_9,
    OEL_MMAN_COVERAGE_10,
    OEL_MMAN_COVERAGE_11,
    OEL_MMAN_COVERAGE_12,
    OEL_MMAN_COVERAGE_13,
    OEL_MMAN_COVERAGE_14,
    OEL_MMAN_COVERAGE_15,
    OEL_MMAN_COVERAGE_16,
    OEL_MMAN_COVERAGE_17,
    OEL_MMAN_COVERAGE_18,
    OEL_MMAN_COVERAGE_N,
} oel_mman_coverage_t;

/* oel_mman_t data structures and fields */
typedef struct _oel_mman
{
    /* Magic number (OEL_MMAN_MAGIC) */
    uint64_t magic;

    /* True if oel_mman_init() has been called */
    bool initialized;

    /* Base of heap (aligned on page boundary) */
    uintptr_t base;

    /* Size of heap (a multiple of OEL_PAGE_SIZE) */
    size_t size;

    /* Start of heap (immediately aft4er VADs array) */
    uintptr_t start;

    /* End of heap (points to first page after end of heap) */
    uintptr_t end;

    /* Current break value: top of break memory partition (grows positively) */
    uintptr_t brk;

    /* Current map value: top of mapped memory partition (grows negatively) */
    uintptr_t map;

    /* The next available oel_vad_t in the VADs array */
    oel_vad_t* next_vad;

    /* The end of the VADs array */
    oel_vad_t* end_vad;

    /* The oel_vad_t free list (singly linked) */
    oel_vad_t* free_vads;

    /* Linked list of VADs (sorted by address and doubly linked) */
    oel_vad_t* vad_list;

    /* Whether sanity checks are enabled: see OEL_HeapEnableSanityChecks() */
    bool sanity;

    /* Whether to scrub memory when it is unmapped (fill with 0xDD) */
    bool scrub;

    /* Heap locking */
    uint64_t lock[8];

    /* Error string */
    char err[OEL_MMAN_ERROR_SIZE];

    /* Code coverage array */
    bool coverage[OEL_MMAN_COVERAGE_N];

} oel_mman_t;

int oel_mman_init(oel_mman_t* heap, uintptr_t base, size_t size);

int oel_mman_map(
    oel_mman_t* heap,
    void* addr,
    size_t length,
    int prot,
    int flags,
    void** ptr);

int oel_mman_mremap(
    oel_mman_t* heap,
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags,
    void** ptr);

int oel_mman_munmap(oel_mman_t* heap, void* address, size_t size);

void oel_mman_dump(const oel_mman_t* h, bool full);

int oel_mman_sbrk(oel_mman_t* heap, ptrdiff_t increment, void** ptr);

int oel_mman_brk(oel_mman_t* heap, void* addr);

void oel_mman_set_sanity(oel_mman_t* heap, bool sanity);

bool oel_mman_is_sane(oel_mman_t* heap);

#endif /* _OEL_INTERNAL_MMAN_H */
