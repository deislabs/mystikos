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

#endif /* _LIBOS_REGIONS_H */
