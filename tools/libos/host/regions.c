// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/bits/sgx/region.h>
#include <libos/elf.h>
#include <libos/round.h>
#include <libos/eraise.h>
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
#define MMAN_SIZE (64 * MEGABYTE)

region_details _details = { 0 };

static int _load_file(const char* path, size_t extra_space, void** data_out, size_t* size_out)
{
    int ret = -1;
    FILE* is = NULL;
    void* data = NULL;
    size_t size;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    /* Check parameters */
    if (!path || !data_out || !size_out)
        goto done;

    /* Get size of this file */
    {
        struct stat buf;

        if (stat(path, &buf) != 0)
            goto done;

        size = buf.st_size;
    }

    /* Allocate memory */
    if (!(data = malloc(size + extra_space)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(data, 1, size, is) != size)
        goto done;

    *size_out = size;
    *data_out = data;
    data = NULL;
    ret = 0;

done:

    if (data)
        free(data);

    if (is)
        fclose(is);

    return ret;
}

const region_details * create_region_details(
    const char* program_path,
    const char* rootfs_path)
{
    region_details* rd =  &_details;

    rd->mman_size = MMAN_SIZE;

    if (_load_file(rootfs_path, 0, &rd->rootfs_data, &rd->rootfs_size) != 0)
        _err("failed to load load rootfs: %s", rootfs_path);

    if (program_path[0] != '/')
    {
        _err("program must be an absolute path within the rootfs: %s",
            program_path);
    }

    /* Find libosenc.so, liboscrt.so, and liboskernel.so */
    {
        if (format_libosenc(rd->enc_path, sizeof(rd->enc_path)) != 0)
            _err("failed to form libosenc.so path");

        if (format_liboscrt(rd->crt_path, sizeof(rd->crt_path)) != 0)
            _err("failed to form liboscrt.so path");

        if (format_liboskernel(rd->kernel_path, sizeof(rd->kernel_path)) != 0)
            _err("failed to form liboskernel.so path");

        if (access(rd->enc_path, R_OK) != 0)
            _err("cannot find: %s", rd->enc_path);

        if (access(rd->crt_path, R_OK) != 0)
            _err("cannot find: %s", rd->crt_path);

        if (access(rd->kernel_path, R_OK) != 0)
            _err("cannot find: %s", rd->kernel_path);
    }

    /* Load the C runtime and kernel ELF image into memory */
    if (elf_image_load(rd->crt_path, &rd->crt_image) != 0)
        _err("failed to load C runtime image: %s", rd->crt_path);

    if (elf_image_load(rd->kernel_path, &rd->kernel_image) != 0)
        _err("failed to load kernel image: %s", rd->kernel_path);

    return &_details;
}

void free_region_details()
{
    free(_details.rootfs_data);
    elf_image_free(&_details.crt_image);
    elf_image_free(&_details.kernel_image);
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
    assert(_details.crt_image.image_data != NULL);
    assert(_details.crt_image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, CRT_REGION_ID, true, _details.crt_path) != OE_OK)
        ERAISE(-EINVAL);

    ECHECK(_load_crt_pages(context, &_details.crt_image, *vaddr));

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

    *vaddr += libos_round_up_to_page_size(_details.crt_image.image_size);

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
    assert(_details.kernel_image.image_data != NULL);
    assert(_details.kernel_image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, KERNEL_REGION_ID, true, _details.kernel_path) != OE_OK)
        ERAISE(-EINVAL);

    ECHECK(_load_kernel_pages(context, &_details.kernel_image, *vaddr));

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

    *vaddr += libos_round_up_to_page_size(_details.kernel_image.image_size);

done:
    return ret;
}

static int _add_crt_reloc_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    assert(_details.crt_image.reloc_data != NULL);
    assert(_details.crt_image.reloc_size != 0);
    assert((_details.crt_image.reloc_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, CRT_RELOC_REGION_ID, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.crt_image.reloc_data;
        size_t npages = _details.crt_image.reloc_size / PAGE_SIZE;

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
    assert(_details.kernel_image.reloc_data != NULL);
    assert(_details.kernel_image.reloc_size != 0);
    assert((_details.kernel_image.reloc_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, KERNEL_RELOC_REGION_ID, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_details.kernel_image.reloc_data;
        size_t npages = _details.kernel_image.reloc_size / PAGE_SIZE;

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
    const uint8_t* p = _details.rootfs_data;
    size_t n = _details.rootfs_size;
    size_t r = n;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    assert(_details.rootfs_data != NULL);
    assert(_details.rootfs_size != 0);

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

    return OE_OK;
}
