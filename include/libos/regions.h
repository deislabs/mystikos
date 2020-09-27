#ifndef _LIBOS_REGIONS_H
#define _LIBOS_REGIONS_H

#include <libos/types.h>

/* memory region identifiers for the libos image */

#define LIBOS_KERNEL_REGION_ID 1
#define LIBOS_KERNEL_RELOC_REGION_ID 2
#define LIBOS_CRT_REGION_ID 3
#define LIBOS_CRT_RELOC_REGION_ID 4
#define LIBOS_ROOTFS_REGION_ID 5
#define LIBOS_MMAN_REGION_ID 6
#define LIBOS_CONFIG_REGION_ID 7
#define LIBOS_KERNEL_SYMTAB_REGION_ID 8 /* .symtab section */
#define LIBOS_KERNEL_STRTAB_REGION_ID 9 /* .strtab section */
#define LIBOS_KERNEL_DYNSYM_REGION_ID 10 /* .dynsym section */
#define LIBOS_KERNEL_DYNSTR_REGION_ID 11 /* .dynstr section */

#endif /* _LIBOS_REGIONS_H */
