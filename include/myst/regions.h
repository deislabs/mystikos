// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_REGIONS_H
#define _MYST_REGIONS_H

#include <myst/types.h>

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

#endif /* _MYST_REGIONS_H */
