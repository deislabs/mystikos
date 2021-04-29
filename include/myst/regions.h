// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_REGIONS_H
#define _MYST_REGIONS_H

#include <stdint.h>
#include <sys/mman.h>

#include <myst/defs.h>

#define MYST_REGION_MAGIC 0x1c8093ca739f4e61
#define MYST_REGION_NAME_SIZE 256
#define MYST_REGION_EXTEND 128

/* memory region identifiers */
#define MYST_REGION_CONFIG "config"
#define MYST_REGION_KERNEL_STACKS "kernel.stacks"
#define MYST_REGION_KERNEL "kernel"
#define MYST_REGION_KERNEL_RELOC "kernel.reloc"
#define MYST_REGION_KERNEL_SYMTAB "kernel.symtab" /* .symtab section */
#define MYST_REGION_KERNEL_STRTAB "kernel.strtab" /* .strtab section */
#define MYST_REGION_KERNEL_DYNSYM "kernel.dynsym" /* .dynsym section */
#define MYST_REGION_KERNEL_DYNSTR "kernel.dynstr" /* .dynstr section */
#define MYST_REGION_CRT "crt"
#define MYST_REGION_CRT_RELOC "crt.reloc"
#define MYST_REGION_ROOTFS "rootfs"
#define MYST_REGION_MMAN "mman"
#define MYST_REGION_ARCHIVE "archive"
#define MYST_REGION_KERNEL_ENTER_STACK "kernel.enter.stack"

typedef struct myst_region_trailer
{
    uint64_t magic;
    char name[MYST_REGION_NAME_SIZE];
    uint64_t size;
    uint64_t index; /* index of this trailer [0:N] */
    uint8_t padding[3816];
} myst_region_trailer_t;

typedef struct myst_region
{
    void* data;
    size_t size;
} myst_region_t;

MYST_STATIC_ASSERT(sizeof(myst_region_trailer_t) == 4096);

typedef int (*myst_add_page_t)(
    void* arg,
    uint64_t vaddr,
    const void* page,
    int flags); /* PROT_READ, PROT_WRITE, PROT_EXEC, MYST_REGION_EXTEND */

typedef struct myst_region_context myst_region_context_t;

int myst_region_init(
    myst_add_page_t add_page,
    void* add_page_arg,
    myst_region_context_t** context);

int myst_region_release(myst_region_context_t* context);

int myst_region_open(myst_region_context_t* context);

int myst_region_close(
    myst_region_context_t* context,
    const char* name,
    uint64_t vaddr);

int myst_region_add_page(
    myst_region_context_t* context,
    uint64_t vaddr,
    const void* page,
    int flags); /* PROT_READ, PROT_WRITE, PROT_EXEC, MYST_REGION_EXTEND */

int myst_region_find(
    const void* regions_end,
    const char* name,
    myst_region_t* region);

#endif /* _MYST_REGIONS_H */
