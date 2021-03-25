// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_REGION_H
#define _MYST_REGION_H

#include <stdint.h>
#include <sys/mman.h>

#include <myst/defs.h>

/* memory region identifiers for the myst image */

#define MYST_KERNEL_REGION_ID 1
#define MYST_KERNEL_RELOC_REGION_ID 2
#define MYST_CRT_REGION_ID 3
#define MYST_CRT_RELOC_REGION_ID 4
#define MYST_ROOTFS_REGION_ID 5
#define MYST_MMAN_REGION_ID 6
#define MYST_CONFIG_REGION_ID 7
#define MYST_KERNEL_SYMTAB_REGION_ID 8  /* .symtab section */
#define MYST_KERNEL_STRTAB_REGION_ID 9  /* .strtab section */
#define MYST_KERNEL_DYNSYM_REGION_ID 10 /* .dynsym section */
#define MYST_KERNEL_DYNSTR_REGION_ID 11 /* .dynstr section */
#define MYST_ARCHIVE_REGION_ID 12

#define MYST_REGION_EXTEND 2

#define MYST_REGION_MAGIC 0x1c8093ca739f4e61

#define MYST_REGION_NAME_SIZE 256

typedef struct myst_region_trailer
{
    uint64_t magic;
    char name[MYST_REGION_NAME_SIZE];
    uint64_t size;
    uint8_t padding[3824];
} myst_region_trailer_t;

MYST_STATIC_ASSERT(sizeof(myst_region_trailer_t) == 4096);

typedef int (*myst_add_page_t)(
    uint64_t vaddr,
    const void* page,
    int prot,  /* (PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE) */
    int flags, /* MYST_REGION_EXTEND */
    void* arg);

typedef struct myst_region_context myst_region_context_t;

int myst_region_init(
    myst_add_page_t add_page,
    void* add_page_arg,
    myst_region_context_t** context);

int myst_region_release(myst_region_context_t* context);

int myst_region_open(myst_region_context_t* context);

int myst_region_close(myst_region_context_t* context, const char* name);

int myst_region_add_page(
    myst_region_context_t* context,
    uint64_t vaddr,
    const void* page,
    int prot,   /* (PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE) */
    int flags); /* MYST_REGION_EXTEND */

#endif /* _MYST_REGION_H */
