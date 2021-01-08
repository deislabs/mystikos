// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "regions.h"
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <myst/elf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/round.h>
#include <myst/strings.h>
#include <limits.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/host.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../config.h"
#include "../shared.h"
#include "utils.h"

/* ATTN: use common header */
// 64MB = 64*1024*1024/4096
#define MMAN_DEFAULT_PAGES 16384

region_details _details = {0};

const region_details* create_region_details_from_package(
    elf_image_t* myst_elf,
    size_t user_pages)
{
    char dir[PATH_MAX];

    strcpy(dir, get_program_file());
    dirname(dir);

    if (snprintf(
            _details.enc.path,
            sizeof(_details.enc.path),
            "%s/lib/openenclave/mystenc.so",
            dir) >= sizeof(_details.enc.path))
        _err("buffer overflow when forming mystenc.so path");

    // Load CRT
    if (elf_image_from_section(
            myst_elf,
            ".libmystcrt",
            &_details.crt.image,
            (const void**)&_details.crt.buffer,
            &_details.crt.buffer_size) != 0)
    {
        _err("failed to extract CRT section from : %s", get_program_file());
    }
    _details.crt.status = REGION_ITEM_BORROWED;

    // Load Kernel
    if (elf_image_from_section(
            myst_elf,
            ".libmystkernel",
            &_details.kernel.image,
            (const void**)&_details.kernel.buffer,
            &_details.kernel.buffer_size) != 0)
    {
        _err("failed to extract kernel section from : %s", get_program_file());
    }
    _details.kernel.status = REGION_ITEM_BORROWED;

    // Load ROOTFS
    if (elf_find_section(
            &myst_elf->elf,
            ".mystrootfs",
            (unsigned char**)&_details.rootfs.buffer,
            &_details.rootfs.buffer_size) != 0)
    {
        _err("Failed to extract rootfs from %s.", get_program_file());
    }
    _details.rootfs.status = REGION_ITEM_BORROWED;

    // Load config data
    if (elf_find_section(
            &myst_elf->elf,
            ".mystconfig",
            (unsigned char**)&_details.config.buffer,
            &_details.config.buffer_size) == 0)
    {
        if (user_pages == 0)
        {
            config_parsed_data_t parsed_data = {0};
            if (parse_config_from_buffer(
                    _details.config.buffer,
                    _details.config.buffer_size,
                    &parsed_data) == 0)
            {
                user_pages = parsed_data.user_pages;
                free_config(&parsed_data);
            }
            else
                _err("Failed to parse config we extracted from enclave");
        }
    }
    else
        _err("Failed to extract config data from %s.", get_program_file());

    _details.config.status = REGION_ITEM_BORROWED;

    if (user_pages == 0)
        user_pages = MMAN_DEFAULT_PAGES;
    _details.mman_size = user_pages * PAGE_SIZE;

    return &_details;
}

const region_details* get_region_details(void)
{
    return &_details;
}

const region_details* create_region_details_from_files(
    const char* program_path,
    const char* rootfs_path,
    const char* config_path,
    size_t user_pages)
{
    if (myst_load_file(
            rootfs_path,
            &_details.rootfs.buffer,
            &_details.rootfs.buffer_size) != 0)
        _err("failed to load rootfs: %s", rootfs_path);
    _details.rootfs.status = REGION_ITEM_OWNED;

    if (program_path[0] != '/')
    {
        _err(
            "program must be an absolute path within the rootfs: %s",
            program_path);
    }

    /* Find mystenc.so, libmystcrt.so, and libmystkernel.so */
    {
        if (format_mystenc(_details.enc.path, sizeof(_details.enc.path)) != 0)
            _err("buffer overflow when forming mystenc.so path");

        if (format_libmystcrt(_details.crt.path, sizeof(_details.crt.path)) != 0)
            _err("buffer overflow when forming libmystcrt.so path");

        if (format_libmystkernel(
                _details.kernel.path, sizeof(_details.kernel.path)) != 0)
            _err("buffer overflow when forming libmystcrt.so path");

        if (access(_details.enc.path, R_OK) != 0)
            _err("cannot find: %s", _details.enc.path);

        if (access(_details.crt.path, R_OK) != 0)
            _err("cannot find: %s", _details.crt.path);

        if (access(_details.kernel.path, R_OK) != 0)
            _err("cannot find: %s", _details.kernel.path);
    }

    /* Load the C runtime and kernel ELF image into memory */
    if (elf_image_load(_details.crt.path, &_details.crt.image) != 0)
        _err("failed to load C runtime image: %s", _details.crt.path);
    _details.crt.status = REGION_ITEM_OWNED;

    if (elf_image_load(_details.kernel.path, &_details.kernel.image) != 0)
        _err("failed to load kernel image: %s", _details.kernel.path);
    _details.kernel.status = REGION_ITEM_OWNED;

    if (config_path)
    {
        // if we have the configuration load it
        if (myst_load_file(
                config_path,
                (void**)&_details.config.buffer,
                &_details.config.buffer_size) != 0)
            _err("failed to load config: %s", rootfs_path);
        _details.config.status = REGION_ITEM_OWNED;
    }
    else
    {
        // We have no configuration, but we can take a look in the enclave
        // itself to see if it has been stored there!
        elf_t enc_elf = {0};

        if (elf_load(_details.enc.path, &enc_elf) != 0)
            _err("failed to load enclave image: %s", _details.enc.path);

        unsigned char* temp_buf;
        size_t temp_size;
        if (elf_find_section(&enc_elf, ".mystconfig", &temp_buf, &temp_size) ==
            0)
        {
            // We are going to have to duplicate this buffer so we can unload
            // the enclave image
            _details.config.buffer = malloc(temp_size);
            if (_details.config.buffer == NULL)
                _err("out of memory");
            memcpy(_details.config.buffer, temp_buf, temp_size);
            _details.config.buffer_size = temp_size;
            _details.config.status = REGION_ITEM_OWNED;

            // If we dont have the user_pages yet then we can extract them from
            // the config.
            if (user_pages == 0)
            {
                config_parsed_data_t parsed_data = {0};
                if (parse_config_from_buffer(
                        _details.config.buffer, temp_size, &parsed_data) == 0)
                {
                    user_pages = parsed_data.user_pages;
                    free_config(&parsed_data);
                }
                else
                    _err("Failed to parse config we extracted from enclave");
            }
        }
        else
        {
            // This is not a signed enclave so we have no config
        }
        elf_unload(&enc_elf);
    }

    if (user_pages == 0)
        user_pages = MMAN_DEFAULT_PAGES;
    _details.mman_size = user_pages * PAGE_SIZE;

    return &_details;
}

void free_region_details()
{
    if (_details.rootfs.status == REGION_ITEM_OWNED)
        free(_details.rootfs.buffer);
    if (_details.crt.status == REGION_ITEM_OWNED)
        elf_image_free(&_details.crt.image);
    if (_details.kernel.status == REGION_ITEM_OWNED)
        elf_image_free(&_details.kernel.image);
    if (_details.config.status == REGION_ITEM_OWNED)
        free(_details.config.buffer);

    /* delete the temporary file if any */
    if (strncmp(_details.kernel.path, "/tmp/myst", 10) == 0)
        unlink(_details.kernel.path);
}

static int _add_segment_pages(
    oe_region_context_t* context,
    const elf_segment_t* segment,
    const void* image_base,
    uint64_t vaddr)
{
    int ret = 0;
    uint64_t page_vaddr = myst_round_down_to_page_size(segment->vaddr);
    uint64_t segment_end = segment->vaddr + segment->memsz;

    for (; page_vaddr < segment_end; page_vaddr += PAGE_SIZE)
    {
        const uint64_t dest_vaddr = vaddr + page_vaddr;
        const void* page = (uint8_t*)image_base + page_vaddr;
        uint64_t flags = SGX_SECINFO_REG;
        const bool extend = true;

        if (segment->flags & PF_R)
            flags |= SGX_SECINFO_R;

        if (segment->flags & PF_W)
            flags |= SGX_SECINFO_W;

        if (segment->flags & PF_X)
            flags |= SGX_SECINFO_X;

        if (oe_region_add_page(context, dest_vaddr, page, flags, extend) !=
            OE_OK)
        {
            ERAISE(-EINVAL);
        }
    }

    ret = 0;

done:
    return ret;
}

static int _load_crt_pages(
    oe_region_context_t* context,
    elf_image_t* image,
    uint64_t vaddr)
{
    int ret = 0;

    if (!context || !image)
        ERAISE(-EINVAL);

    assert((image->image_size & (PAGE_SIZE - 1)) == 0);

    /* Add the program segments first */
    for (size_t i = 0; i < image->num_segments; i++)
    {
        ECHECK(_add_segment_pages(
            context, &image->segments[i], image->image_data, vaddr));
    }

    ret = 0;

done:
    return ret;
}

static int _add_crt_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const uint64_t id = MYST_CRT_REGION_ID;
    uint64_t r;

    assert(_details.crt.image.image_data != NULL);
    assert(_details.crt.image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    ECHECK(_load_crt_pages(context, &_details.crt.image, *vaddr));

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

    const uint64_t m = PAGE_SIZE;
    ECHECK(myst_round_up(_details.crt.image.image_size, m, &r));
    *vaddr += r;

done:
    return ret;
}

static int _load_kernel_pages(
    oe_region_context_t* context,
    elf_image_t* image,
    uint64_t vaddr)
{
    int ret = 0;

    if (!context || !image)
        ERAISE(-EINVAL);

    assert((image->image_size & (PAGE_SIZE - 1)) == 0);

    /* Add the program segments first */
    for (size_t i = 0; i < image->num_segments; i++)
    {
        ECHECK(_add_segment_pages(
            context, &image->segments[i], image->image_data, vaddr));
    }

    ret = 0;

done:
    return ret;
}

static int _add_kernel_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const uint64_t id = MYST_KERNEL_REGION_ID;
    int fd = -1;
    uint64_t r;

    assert(_details.kernel.image.image_data != NULL);
    assert(_details.kernel.image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    char* path = NULL;
    if (_details.kernel.path[0] != 0)
        path = _details.kernel.path;

    /* packaged case: create temporary file where oegdb can read symbols */
    if (!path)
    {
        char template[] = "/tmp/mystXXXXXX";

        if ((fd = mkstemp(template)) < 0)
            goto done;

        /* write the ELF file to disk */
        ECHECK(myst_write_file_fd(
            fd, _details.kernel.buffer, _details.kernel.buffer_size));

        /* save the path so it can be deleted later */
        path = _details.kernel.path;
        myst_strlcpy(path, template, sizeof(_details.kernel.path));
    }

    if (oe_region_start(context, id, true, path) != OE_OK)
        ERAISE(-EINVAL);

    ECHECK(_load_kernel_pages(context, &_details.kernel.image, *vaddr));

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

    const uint64_t m = PAGE_SIZE;
    ECHECK(myst_round_up(_details.kernel.image.image_size, m, &r));
    *vaddr += r;

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _add_crt_reloc_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    const uint64_t id = MYST_CRT_RELOC_REGION_ID;

    assert(_details.crt.image.reloc_data != NULL);
    assert(_details.crt.image.reloc_size != 0);
    assert((_details.crt.image.reloc_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.crt.image.reloc_data;
        size_t npages = _details.crt.image.reloc_size / PAGE_SIZE;

        for (size_t i = 0; i < npages; i++)
        {
            const bool extend = true;

            if (oe_region_add_page(
                    context,
                    *vaddr,
                    page,
                    SGX_SECINFO_REG | SGX_SECINFO_R,
                    extend) != OE_OK)
            {
                ERAISE(-EINVAL);
            }

            page += PAGE_SIZE;
            (*vaddr) += PAGE_SIZE;
        }
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_kernel_reloc_region(
    oe_region_context_t* context,
    uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    const uint64_t id = MYST_KERNEL_RELOC_REGION_ID;

    assert(_details.kernel.image.reloc_data != NULL);
    assert(_details.kernel.image.reloc_size != 0);
    assert((_details.kernel.image.reloc_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.kernel.image.reloc_data;
        size_t npages = _details.kernel.image.reloc_size / PAGE_SIZE;

        for (size_t i = 0; i < npages; i++)
        {
            const bool extend = true;

            if (oe_region_add_page(
                    context,
                    *vaddr,
                    page,
                    SGX_SECINFO_REG | SGX_SECINFO_R,
                    extend) != OE_OK)
            {
                ERAISE(-EINVAL);
            }

            page += PAGE_SIZE;
            (*vaddr) += PAGE_SIZE;
        }
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_kernel_symtab_region(
    oe_region_context_t* context,
    uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    const uint64_t id = MYST_KERNEL_SYMTAB_REGION_ID;

    assert(_details.kernel.image.symtab_data != NULL);
    assert(_details.kernel.image.symtab_size != 0);
    assert((_details.kernel.image.symtab_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.kernel.image.symtab_data;
        size_t npages = _details.kernel.image.symtab_size / PAGE_SIZE;

        for (size_t i = 0; i < npages; i++)
        {
            const bool extend = true;

            if (oe_region_add_page(
                    context,
                    *vaddr,
                    page,
                    SGX_SECINFO_REG | SGX_SECINFO_R,
                    extend) != OE_OK)
            {
                ERAISE(-EINVAL);
            }

            page += PAGE_SIZE;
            (*vaddr) += PAGE_SIZE;
        }
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_kernel_dynsym_region(
    oe_region_context_t* context,
    uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    const uint64_t id = MYST_KERNEL_DYNSYM_REGION_ID;

    assert(_details.kernel.image.dynsym_data != NULL);
    assert(_details.kernel.image.dynsym_size != 0);
    assert((_details.kernel.image.dynsym_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.kernel.image.dynsym_data;
        size_t npages = _details.kernel.image.dynsym_size / PAGE_SIZE;

        for (size_t i = 0; i < npages; i++)
        {
            const bool extend = true;

            if (oe_region_add_page(
                    context,
                    *vaddr,
                    page,
                    SGX_SECINFO_REG | SGX_SECINFO_R,
                    extend) != OE_OK)
            {
                ERAISE(-EINVAL);
            }

            page += PAGE_SIZE;
            (*vaddr) += PAGE_SIZE;
        }
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_kernel_strtab_region(
    oe_region_context_t* context,
    uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    const uint64_t id = MYST_KERNEL_STRTAB_REGION_ID;

    assert(_details.kernel.image.strtab_data != NULL);
    assert(_details.kernel.image.strtab_size != 0);
    assert((_details.kernel.image.strtab_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.kernel.image.strtab_data;
        size_t npages = _details.kernel.image.strtab_size / PAGE_SIZE;

        for (size_t i = 0; i < npages; i++)
        {
            const bool extend = true;

            if (oe_region_add_page(
                    context,
                    *vaddr,
                    page,
                    SGX_SECINFO_REG | SGX_SECINFO_R,
                    extend) != OE_OK)
            {
                ERAISE(-EINVAL);
            }

            page += PAGE_SIZE;
            (*vaddr) += PAGE_SIZE;
        }
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_kernel_dynstr_region(
    oe_region_context_t* context,
    uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    const uint64_t id = MYST_KERNEL_DYNSTR_REGION_ID;

    assert(_details.kernel.image.dynstr_data != NULL);
    assert(_details.kernel.image.dynstr_size != 0);
    assert((_details.kernel.image.dynstr_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.kernel.image.dynstr_data;
        size_t npages = _details.kernel.image.dynstr_size / PAGE_SIZE;

        for (size_t i = 0; i < npages; i++)
        {
            const bool extend = true;

            if (oe_region_add_page(
                    context,
                    *vaddr,
                    page,
                    SGX_SECINFO_REG | SGX_SECINFO_R,
                    extend) != OE_OK)
            {
                ERAISE(-EINVAL);
            }

            page += PAGE_SIZE;
            (*vaddr) += PAGE_SIZE;
        }
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_rootfs_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const uint8_t* p = _details.rootfs.buffer;
    size_t n = _details.rootfs.buffer_size;
    size_t r = n;
    const uint64_t id = MYST_ROOTFS_REGION_ID;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    assert(_details.rootfs.buffer != NULL);
    assert(_details.rootfs.buffer_size != 0);

    if (oe_region_start(context, id, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    while (r)
    {
        __attribute__((__aligned__(PAGE_SIZE))) uint8_t page[PAGE_SIZE];
        const bool extend = true;
        const size_t min = (r < sizeof(page)) ? r : sizeof(page);

        memcpy(page, p, min);

        if (min < sizeof(page))
            memset(page + r, 0, sizeof(page) - r);

        if (oe_region_add_page(
                context,
                *vaddr,
                page,
                SGX_SECINFO_REG | SGX_SECINFO_R,
                extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
        p += min;
        r -= min;
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_config_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const uint8_t* p = (uint8_t*)_details.config.buffer;
    size_t n = _details.config.buffer_size;
    size_t r = n;
    const uint64_t id = MYST_CONFIG_REGION_ID;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    // If we have no config then we cannot add this region
    if (_details.config.buffer == NULL)
    {
        return 0;
    }

    if (oe_region_start(context, id, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    while (r)
    {
        __attribute__((__aligned__(PAGE_SIZE))) uint8_t page[PAGE_SIZE];
        const bool extend = true;
        const size_t min = (r < sizeof(page)) ? r : sizeof(page);

        memcpy(page, p, min);

        if (min < sizeof(page))
            memset(page + r, 0, sizeof(page) - r);

        if (oe_region_add_page(
                context,
                *vaddr,
                page,
                SGX_SECINFO_REG | SGX_SECINFO_R,
                extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
        p += min;
        r -= min;
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_mman_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    __attribute__((__aligned__(PAGE_SIZE))) uint8_t page[PAGE_SIZE];
    const size_t mman_pages = _details.mman_size / PAGE_SIZE;
    const uint64_t id = MYST_MMAN_REGION_ID;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, id, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    memset(page, 0, sizeof(page));

    /* Add the leading guard page */
    {
        const bool extend = true;

        if (oe_region_add_page(
                context, *vaddr, page, SGX_SECINFO_REG, extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
    }

    for (size_t i = 0; i < mman_pages; i++)
    {
        const bool extend = false;

        if (oe_region_add_page(
                context,
                *vaddr,
                page,
                SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X,
                extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
    }

    /* Add the trailing guard page */
    {
        const bool extend = true;

        if (oe_region_add_page(
                context, *vaddr, page, SGX_SECINFO_REG, extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

oe_result_t oe_region_add_regions(oe_region_context_t* context, uint64_t vaddr)
{
    if (_add_kernel_region(context, &vaddr) != 0)
        _err("_add_kernel_region() failed");

    if (_add_kernel_reloc_region(context, &vaddr) != 0)
        _err("_add_kernel_reloc_region() failed");

    if (_add_kernel_symtab_region(context, &vaddr) != 0)
        _err("_add_kernel_symtab_region() failed");

    if (_add_kernel_dynsym_region(context, &vaddr) != 0)
        _err("_add_kernel_dynsym_region() failed");

    if (_add_kernel_strtab_region(context, &vaddr) != 0)
        _err("_add_kernel_strtab_region() failed");

    if (_add_kernel_dynstr_region(context, &vaddr) != 0)
        _err("_add_kernel_dynstr_region() failed");

    if (_add_crt_region(context, &vaddr) != 0)
        _err("_add_crt_region() failed");

    if (_add_crt_reloc_region(context, &vaddr) != 0)
        _err("_add_crt_reloc_region() failed");

    if (_add_rootfs_region(context, &vaddr) != 0)
        _err("_add_rootfs_region() failed");

    if (_add_mman_region(context, &vaddr) != 0)
        _err("_add_mman_region() failed");

    if (_add_config_region(context, &vaddr) != 0)
        _err("_add_config_region() failed");

    return OE_OK;
}
