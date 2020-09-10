// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/elf.h>
#include <libos/file.h>
#include <limits.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

const char* arg0;

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
    // printf("=== _callback(): %s\n", msg);
    strcpy(_msg, msg);
}

static int _test_image_load(const char* path)
{
    elf_image_t image;
    uint8_t* data = NULL;

    if (elf_image_load(path, &image) != 0)
    {
        fprintf(stderr, "%s: failed to load image: %s\n", arg0, path);
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
            fprintf(stderr, "%s: out of memory\n", arg0);
            exit(1);
        }

        memset(data, 0, size);

        if (mprotect(data, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            fprintf(stderr, "%s: mprotect() failed\n", arg0);
            exit(1);
        }

        memcpy(data, image.image_data, image.image_size);
    }

    /* Call into the newly loaded image */
    {
        const uint8_t magic[] = {0x7f, 'E', 'L', 'F'};
        typedef int (*entry_t)(void (*callback)(const char* msg));
        entry_t entry;
        int r;

        elf_ehdr_t* ehdr = (elf_ehdr_t*)data;

        if (memcmp(ehdr->e_ident, magic, sizeof(magic)) != 0)
        {
            fprintf(stderr, "%s: bad elf magic\n", arg0);
            exit(1);
        }

        entry = (entry_t)(data + ehdr->e_entry);
        r = (*entry)(_callback);
        assert(r == 12345);
        assert(strcmp(_msg, "hello from the ELF image") == 0);
    }

    elf_image_free(&image);
    free(data);

    printf("=== passed test (%s: %s)\n", arg0, __FUNCTION__);

    return 0;
}

static int _test_add_section(const char* path)
{
    elf_t elf = ELF64_INIT;
    elf_t new_elf = ELF64_INIT;
    void* data = NULL;
    size_t size;
    char new_path[PATH_MAX];
    uint8_t* new_data;
    size_t new_size;

    if (elf_load(path, &elf) != 0)
    {
        fprintf(stderr, "%s: failed to load ELF image: %s \n", arg0, path);
        exit(1);
    }

    if (libos_load_file(arg0, &data, &size) != 0)
    {
        fprintf(stderr, "%s: failed to load file: %s \n", arg0, arg0);
        exit(1);
    }

    if (elf_add_section(&elf, ".mysection", SHT_PROGBITS, data, size) != 0)
    {
        fprintf(stderr, "%s: failed to add section\n", arg0);
        exit(1);
    }

    if (snprintf(new_path, PATH_MAX, "%s.new", path) >= PATH_MAX)
    {
        fprintf(stderr, "%s: path overflow\n", arg0);
        exit(1);
    }

    if (libos_write_file(new_path, elf.data, elf.size) != 0)
    {
        fprintf(stderr, "%s: failed to write file\n", arg0);
        exit(1);
    }

#if 0
    printf("Created %s\n", new_path);
#endif

    elf_unload(&elf);

    /* Load the new elf image */
    if (elf_load(new_path, &new_elf) != 0)
    {
        fprintf(stderr, "%s: failed to load ELF image: %s \n", arg0, new_path);
        exit(1);
    }

    /* Find the section in the new ELF image */
    if (elf_find_section(&new_elf, ".mysection", &new_data, &new_size) != 0)
    {
        fprintf(stderr, "%s: failed to find section\n", arg0);
        exit(1);
    }

    assert(new_size == size);
    assert(memcmp(data, new_data, size) == 0);

    printf("=== passed test (%s: %s)\n", arg0, __FUNCTION__);

    free(data);
    elf_unload(&new_elf);

    return 0;
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <image>\n", argv[0]);
        exit(1);
    }

    _test_image_load(argv[1]);
    _test_add_section(argv[1]);
    return 0;
}
