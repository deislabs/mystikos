// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MYST_HOST_REGIONS_H
#define _MYST_MYST_HOST_REGIONS_H

#include <limits.h>
#include <myst/elf.h>
#include <myst/regions.h>
#include "sections.h"

int add_regions(void* arg, uint64_t baseaddr, myst_add_page_t add_page);

typedef struct _region_details_item
{
    enum
    {
        REGION_ITEM_EMPTY,
        REGION_ITEM_BORROWED,
        REGION_ITEM_OWNED
    } status;
    char path[PATH_MAX];
    elf_image_t image;
    void* buffer;
    size_t buffer_size;
} region_details_item;

typedef struct _region_details
{
    size_t mman_size;
    region_details_item enc;
    region_details_item crt;
    region_details_item kernel;
    region_details_item rootfs;
    region_details_item pubkeys;
    region_details_item roothashes;
    region_details_item config;
} region_details;

const region_details* get_region_details(void);

const region_details* create_region_details_from_files(
    const char* program_path,
    const char* rootfs_path,
    const char* pubkeys_path,
    const char* roothashes_path,
    const char* config_path,
    size_t ram);

const region_details* create_region_details_from_package(
    sections_t* sections,
    size_t heap_pages);

void free_region_details();

/* map regions onto mmap mapping */
int map_regions(void** addr, size_t* length);

#endif /* _MYST_MYST_HOST_REGIONS_H */
