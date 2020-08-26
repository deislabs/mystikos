// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <libos/elf.h>

void set_region_details(
    elf_image_t* crt_image,
    char* crt_path,
    elf_image_t* kernel_image,
    char* kernel_path,
    void* rootfs_data,
    size_t rootfs_size);
