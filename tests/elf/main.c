// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libos/elf.h>

int main(int argc, const char* argv[])
{
    elf_image_t image;

    if (elf_image_load(argv[0], &image) != 0)
    {
        fprintf(stderr, "%s: failed to load image\n", argv[0]);
        exit(1);
    }

    elf_image_dump(&image);

    elf_image_free(&image);

    return 0;
}
