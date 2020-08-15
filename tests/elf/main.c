// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <limits.h>
#include <assert.h>
#include <libos/elf.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

int _add_page_callback(
    void* arg,
    uint64_t base_addr,
    uint64_t addr,
    uint64_t src,
    bool read,
    bool write,
    bool exec,
    bool extend)
{
    memcpy((void*)addr, (void*)src, PAGE_SIZE);
    return 0;
}

static char _msg[64];

static void _callback(const char* msg)
{
    printf("=== _callback(): %s\n", msg);
    strcpy(_msg, msg);
}

int main(int argc, const char* argv[])
{
    elf_image_t image;
    uint8_t* data = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <image>\n", argv[0]);
        exit(1);
    }

    if (elf_image_load(argv[1], &image) != 0)
    {
        fprintf(stderr, "%s: failed to load image\n", argv[0]);
        exit(1);
    }

#if 0
    elf_image_dump(&image);
#endif

    /* Load the pages into memory */
    {
        const size_t size = image.image_size;

        if (!(data = memalign(PAGE_SIZE, size)))
        {
            fprintf(stderr, "%s: out of memory\n", argv[0]);
            exit(1);
        }

        memset(data, 0, size);

        if (mprotect(data, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            fprintf(stderr, "%s: mprotect() failed\n", argv[0]);
            exit(1);
        }

        memcpy(data, image.image_data, image.image_size);
    }

    /* Call into the newly loaded image */
    {
        const uint8_t magic[] = { 0x7f, 'E', 'L', 'F' };
        typedef int (*entry_t)(void (*callback)(const char* msg));
        entry_t entry;
        int r;

        elf_ehdr_t* ehdr = (elf_ehdr_t*)data;

        if (memcmp(ehdr->e_ident, magic, sizeof(magic)) != 0)
        {
            fprintf(stderr, "%s: bad elf magic\n", argv[0]);
            exit(1);
        }

        entry = (entry_t)(data + ehdr->e_entry);
        r = (*entry)(_callback);
        assert(r == 12345);
        assert(strcmp(_msg, "hello from the ELF image") == 0);
    }

    elf_image_free(&image);
    free(data);

    return 0;
}
