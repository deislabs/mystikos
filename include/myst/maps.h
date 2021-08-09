// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MAPS_H
#define _MYST_MAPS_H

#include <limits.h>
#include <stdint.h>

/*
**==============================================================================
**
** Interface to "/proc/<pid>/maps", which keeps track of memory mappings
**
**==============================================================================
*/

struct myst_mstat
{
    int prot;
    int flags;
};

typedef struct maps
{
    struct maps* next;
    uint64_t start;  /* starting address */
    uint64_t end;    /* ending address */
    int prot;        /* PROT_READ | PROT_WRITE | PROT_EXEC */
    int flags;       /* MAP_SHARED | MAP_PRIVATE */
    uint64_t offset; /* file offset */
    uint32_t major;  /* major device number */
    uint32_t minor;  /* minor device number */
    uint64_t inode;  /* the inode or zero */
    char path[PATH_MAX];
} myst_maps_t;

void myst_maps_dump1(const myst_maps_t* maps);

void myst_maps_dump(const myst_maps_t* maps);

void myst_maps_free(myst_maps_t* maps);

int myst_maps_load(myst_maps_t** maps_out);

void myst_mstat_dump(const struct myst_mstat* buf);

int myst_mstat(
    const myst_maps_t* maps,
    const void* addr,
    struct myst_mstat* buf);

#endif /* _MYST_MAPS_H */
