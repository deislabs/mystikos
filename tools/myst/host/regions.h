// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <limits.h>
#include <myst/elf.h>

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
    size_t oe_num_heap_pages;
    region_details_item enc;
    region_details_item crt;
    region_details_item kernel;
    region_details_item rootfs;
    region_details_item archive;
    region_details_item config;
} region_details;

const region_details* get_region_details(void);

const region_details* create_region_details_from_files(
    const char* program_path,
    const char* rootfs_path,
    const char* archive_path,
    const char* config_path,
    size_t user_mem_size);

const region_details* create_region_details_from_package(
    elf_image_t* myst_elf,
    size_t user_pages);

void free_region_details();
