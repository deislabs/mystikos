// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/bits/sgx/region.h>
#include <libos/elf.h>
#include <libos/round.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include "utils.h"
#include "../shared.h"
#include "regions.h"

/* ATTN: use common header */
#define PAGE_SIZE 4096
#define MEGABYTE (1024UL * 1024UL)
#define MMAN_DEFAULT_PAGES 64
#define MMAN_SIZE (MMAN_DEFAULT_PAGES * MEGABYTE)

region_details _details = { 0 };

const region_details * create_region_details_from_package(elf_image_t* libos_elf, size_t user_pages)
{
    char dir[PATH_MAX];

    if (user_pages == 0)
        user_pages = 64;
    _details.mman_size = user_pages * MEGABYTE;

    strcpy(dir, get_program_file());
    dirname(dir);

    if (snprintf(_details.enc.path, sizeof(_details.enc.path), "%s/lib/openenclave/libosenc.so", dir) >= sizeof(_details.enc.path))
        _err("buffer overflow when forming libosenc.so path");

    // Load CRT
    if (elf_image_from_section(libos_elf, ".liboscrt", &_details.crt.image) != 0)
        _err("failed to extract CRT section from : %s", get_program_file());
    _details.crt.status = REGION_ITEM_BORROWED;

    // Load Kernel
    if (elf_image_from_section(libos_elf, ".liboskernel", &_details.kernel.image) != 0)
        _err("failed to extract kernel section from : %s", get_program_file());
    _details.kernel.status = REGION_ITEM_BORROWED;

    // Load ROOTFS
    if (elf_find_section(&libos_elf->elf, ".libosrootfs", (unsigned char**)&_details.rootfs.buffer, &_details.rootfs.buffer_size) != 0)
    {
        _err("Failed to extract rootfs from %s.", get_program_file());
    }
    _details.rootfs.status = REGION_ITEM_BORROWED;

    // Load config data
    if (elf_find_section(&libos_elf->elf, ".libosconfig", (unsigned char**)&_details.config.buffer, &_details.config.buffer_size) != 0)
    {
        _err("Failed to extract config data from %s.", get_program_file());
    }
    _details.config.status = REGION_ITEM_BORROWED;

    return &_details;
}

const region_details * create_region_details_from_files(
    const char *program_path, 
    const char *rootfs_path, 
    const char *config_path,
    size_t user_pages)
{
    if (user_pages == 0)
        user_pages = 64;
    _details.mman_size = user_pages * MEGABYTE;

    if (libos_load_file(rootfs_path, &_details.rootfs.buffer, &_details.rootfs.buffer_size) != 0)
        _err("failed to load rootfs: %s", rootfs_path);
    _details.rootfs.status = REGION_ITEM_OWNED;

    if (program_path[0] != '/')
    {
        _err("program must be an absolute path within the rootfs: %s",
            program_path);
    }

    /* Find libosenc.so, liboscrt.so, and liboskernel.so */
    {
        if (format_libosenc(_details.enc.path, sizeof(_details.enc.path)) != 0)
            _err("buffer overflow when forming libosenc.so path");

        if (format_liboscrt(_details.crt.path, sizeof(_details.crt.path)) != 0)
            _err("buffer overflow when forming liboscrt.so path");

        if (format_liboskernel(_details.kernel.path, sizeof(_details.kernel.path)) != 0)
            _err("buffer overflow when forming liboscrt.so path");

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
        if (libos_load_file(config_path, (void**)&_details.config.buffer, &_details.config.buffer_size) != 0)
            _err("failed to load config: %s", rootfs_path);
        _details.config.status = REGION_ITEM_OWNED;
    }
    else
    {
        // We have no configuration, but we can take a look in the enclave itself to see
        // if it has been stored there!
        elf_t enc_elf = { 0 };

        if (elf_load(_details.enc.path, &enc_elf) != 0)
            _err("failed to load enclave image: %s", _details.enc.path);
        
        unsigned char *temp_buf;
        size_t temp_size;
        if (elf_find_section(&enc_elf, ".libosconfig", &temp_buf, &temp_size) == 0)
        {
            // We are going to have to duplicate this buffer so we can unload the enclave image
            _details.config.buffer = malloc(temp_size);
            if (_details.config.buffer == NULL)
                _err("out of memory");
            memcpy(_details.config.buffer, temp_buf, temp_size);
            _details.config.buffer_size = temp_size;
            _details.config.status = REGION_ITEM_OWNED;
        }
        else
        {
            // This is not a signed enclave so we have no config
        }
        elf_unload(&enc_elf);
    }

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
}

static int _add_segment_pages(
    oe_region_context_t* context,
    const elf_segment_t* segment,
    const void* image_base,
    uint64_t vaddr)
{
    int ret = 0;
    uint64_t page_vaddr = libos_round_down_to_page_size(segment->vaddr);
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

        if (oe_region_add_page(
            context,
            dest_vaddr,
            page,
            flags,
            extend) != OE_OK)
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
            context,
            &image->segments[i],
            image->image_data,
            vaddr));
    }

    ret = 0;

done:
    return ret;
}

static int _add_crt_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    assert(_details.crt.image.image_data != NULL);
    assert(_details.crt.image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    char *path = NULL;
    if (_details.crt.path[0] != 0)
        path = _details.crt.path;

    if (oe_region_start(context, CRT_REGION_ID, true, path) != OE_OK)
        ERAISE(-EINVAL);

    ECHECK(_load_crt_pages(context, &_details.crt.image, *vaddr));

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

    *vaddr += libos_round_up_to_page_size(_details.crt.image.image_size);

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
            context,
            &image->segments[i],
            image->image_data,
            vaddr));
    }

    ret = 0;

done:
    return ret;
}

static int _add_kernel_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    assert(_details.kernel.image.image_data != NULL);
    assert(_details.kernel.image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    char *path = NULL;
    if (_details.kernel.path[0] != 0)
        path = _details.kernel.path;

    if (oe_region_start(context, KERNEL_REGION_ID, true, path) != OE_OK)
        ERAISE(-EINVAL);

    ECHECK(_load_kernel_pages(context, &_details.kernel.image, *vaddr));

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

    *vaddr += libos_round_up_to_page_size(_details.kernel.image.image_size);

done:
    return ret;
}

static int _add_crt_reloc_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    assert(_details.crt.image.reloc_data != NULL);
    assert(_details.crt.image.reloc_size != 0);
    assert((_details.crt.image.reloc_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, CRT_RELOC_REGION_ID, is_elf, NULL) != OE_OK)
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
    assert(_details.kernel.image.reloc_data != NULL);
    assert(_details.kernel.image.reloc_size != 0);
    assert((_details.kernel.image.reloc_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, KERNEL_RELOC_REGION_ID, is_elf, NULL) != OE_OK)
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

static int _add_rootfs_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const uint8_t* p = _details.rootfs.buffer;
    size_t n = _details.rootfs.buffer_size;
    size_t r = n;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    assert(_details.rootfs.buffer != NULL);
    assert(_details.rootfs.buffer_size != 0);

    if (oe_region_start(context, ROOTFS_REGION_ID, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    while (r)
    {
        __attribute__((__aligned__(4096)))
        uint8_t page[LIBOS_PAGE_SIZE];
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

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    // If we have no config then we cannot add this region
    if(_details.config.buffer == NULL)
    {
        return 0;
    }

    if (oe_region_start(context, CONFIG_REGION_ID, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    while (r)
    {
        __attribute__((__aligned__(4096)))
        uint8_t page[LIBOS_PAGE_SIZE];
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
    __attribute__((__aligned__(4096)))
    uint8_t page[LIBOS_PAGE_SIZE];
    const size_t mman_pages = _details.mman_size / LIBOS_PAGE_SIZE;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, MMAN_REGION_ID, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    memset(page, 0, sizeof(page));

    /* Add the leading guard page */
    {
        const bool extend = true;

        if (oe_region_add_page(
            context,
            *vaddr,
            page,
            SGX_SECINFO_REG,
            extend) != OE_OK)
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
            SGX_SECINFO_REG|SGX_SECINFO_R|SGX_SECINFO_W|SGX_SECINFO_X,
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
            context,
            *vaddr,
            page,
            SGX_SECINFO_REG,
            extend) != OE_OK)
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
