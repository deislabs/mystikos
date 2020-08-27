// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <libos/elf.h>

typedef struct _region_details
{
    size_t mman_size;
    char enc_path[PATH_MAX];
    elf_image_t crt_image;
    char crt_path[PATH_MAX];
    elf_image_t kernel_image;
    char kernel_path[PATH_MAX];
    void* rootfs_data;
    size_t rootfs_size;
} region_details;

const region_details * create_region_details(const char *program_path, const char *rootfs_path);
void free_region_details();
