// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "regions.h"
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <myst/buf.h>
#include <myst/elf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/hex.h>
#include <myst/round.h>
#include <myst/strings.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../config.h"
#include "../shared.h"
#include "utils.h"

region_details _details = {0};

static int _add_page(
    myst_region_context_t* context,
    uint64_t vaddr,
    const void* page,
    int flags)
{
    return myst_region_add_page(context, vaddr, page, flags);
}

const region_details* create_region_details_from_package(
    elf_image_t* myst_elf,
    size_t heap_pages)
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

    // Load archive:
    if (elf_find_section(
            &myst_elf->elf,
            ".mystarchive",
            (unsigned char**)&_details.archive.buffer,
            &_details.archive.buffer_size) != 0)
    {
        _err("Failed to extract archive from %s.", get_program_file());
    }
    _details.archive.status = REGION_ITEM_BORROWED;

    // Load config data
    if (elf_find_section(
            &myst_elf->elf,
            ".mystconfig",
            (unsigned char**)&_details.config.buffer,
            &_details.config.buffer_size) == 0)
    {
        if (heap_pages == 0)
        {
            config_parsed_data_t parsed_data = {0};
            if (parse_config_from_buffer(
                    _details.config.buffer,
                    _details.config.buffer_size,
                    &parsed_data) == 0)
            {
                heap_pages = parsed_data.heap_pages;
                free_config(&parsed_data);
            }
            else
                _err("Failed to parse config we extracted from enclave");
        }
    }
    else
        _err("Failed to extract config data from %s.", get_program_file());

    _details.config.status = REGION_ITEM_BORROWED;

    if (heap_pages == 0)
        _details.mman_size = DEFAULT_MMAN_SIZE;
    else
        _details.mman_size = heap_pages * PAGE_SIZE;

    return &_details;
}

const region_details* get_region_details(void)
{
    return &_details;
}

const region_details* create_region_details_from_files(
    const char* program_path,
    const char* rootfs_path,
    const char* archive_path,
    const char* config_path,
    size_t ram)
{
    if (myst_load_file(
            rootfs_path,
            &_details.rootfs.buffer,
            &_details.rootfs.buffer_size) != 0)
        _err("failed to load rootfs: %s", rootfs_path);
    _details.rootfs.status = REGION_ITEM_OWNED;

    /* load archive file */
    {
        if (myst_load_file(
                archive_path,
                (void**)&_details.archive.buffer,
                &_details.archive.buffer_size) != 0)
        {
            _err("failed to load archive: %s", archive_path);
        }

        _details.archive.status = REGION_ITEM_OWNED;
    }

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

        if (format_libmystcrt(_details.crt.path, sizeof(_details.crt.path)) !=
            0)
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

    // We need to prioritize enclave resident config before falling back. That
    // way we cannot override the signed configuration path and only use in the
    // unsigned path
    elf_t enc_elf = {0};

    if (elf_load(_details.enc.path, &enc_elf) != 0)
        _err("failed to load enclave image: %s", _details.enc.path);

    unsigned char* temp_buf;
    size_t temp_size;
    if (elf_find_section(&enc_elf, ".mystconfig", &temp_buf, &temp_size) == 0)
    {
        // We are going to have to duplicate this buffer so we can unload
        // the enclave image
        _details.config.buffer = malloc(temp_size);
        if (_details.config.buffer == NULL)
            _err("out of memory");
        memcpy(_details.config.buffer, temp_buf, temp_size);
        _details.config.buffer_size = temp_size;
        _details.config.status = REGION_ITEM_OWNED;

        // We should always use the config value if it is present, otherwise
        // we use what is passed in to the funtion. If it is still zero we
        // will eventually use the default value
        config_parsed_data_t parsed_data = {0};
        if (parse_config_from_buffer(
                _details.config.buffer, temp_size, &parsed_data) == 0)
        {
            ram = parsed_data.heap_pages * PAGE_SIZE;
            free_config(&parsed_data);
        }
        else
        {
            _err("Failed to parse configuration stored in enclave");
        }
    }
    else if (config_path)
    {
        // config in enclave is not there so fall back to the config path is
        // specified
        if (myst_load_file(
                config_path,
                (void**)&_details.config.buffer,
                &_details.config.buffer_size) == 0)
        {
            // We should always use the config value if it is present,
            // otherwise we use what is passed in to the function. If it is
            // still zero we will eventually use the default value
            config_parsed_data_t parsed_data = {0};
            if (parse_config_from_buffer(
                    _details.config.buffer,
                    _details.config.buffer_size,
                    &parsed_data) == 0)
            {
                ram = parsed_data.heap_pages * PAGE_SIZE;
                free_config(&parsed_data);
            }
            else
            {
                _err(
                    "Failed to parse config from specified config path %s",
                    config_path);
            }
        }
        else
            _err("failed to load config: %s", config_path);
        _details.config.status = REGION_ITEM_OWNED;
    }

    elf_unload(&enc_elf);

    if (ram == 0)
    {
        ram = DEFAULT_MMAN_SIZE;
    }

    _details.mman_size = ram;

    return &_details;
}

void free_region_details()
{
    if (_details.rootfs.status == REGION_ITEM_OWNED)
        free(_details.rootfs.buffer);
    if (_details.archive.status == REGION_ITEM_OWNED)
        free(_details.archive.buffer);
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
    myst_region_context_t* context,
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
        int flags = 0;

        if (segment->flags & PF_R)
            flags |= PROT_READ;

        if (segment->flags & PF_W)
            flags |= PROT_WRITE;

        if (segment->flags & PF_X)
            flags |= PROT_EXEC;

        flags |= MYST_REGION_EXTEND;

        if (_add_page(context, dest_vaddr, page, flags) != 0)
        {
            ERAISE(-EINVAL);
        }
    }

    ret = 0;

done:
    return ret;
}

static int _load_crt_pages(
    myst_region_context_t* context,
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

static int _add_crt_region(myst_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const char name[] = MYST_REGION_CRT;
    uint64_t r;

    assert(_details.crt.image.image_data != NULL);
    assert(_details.crt.image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (myst_region_open(context) != 0)
        ERAISE(-EINVAL);

    ECHECK(_load_crt_pages(context, &_details.crt.image, *vaddr));

    const uint64_t m = PAGE_SIZE;
    ECHECK(myst_round_up(_details.crt.image.image_size, m, &r));
    *vaddr += r;

    if (myst_region_close(context, name, *vaddr) != 0)
        ERAISE(-EINVAL);

    *(vaddr) += PAGE_SIZE;

done:
    return ret;
}

static int _load_kernel_pages(
    myst_region_context_t* context,
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

static int _add_kernel_region(
    myst_region_context_t* context,
    uint64_t baseaddr,
    uint64_t* vaddr)
{
    int ret = 0;
    const char name[] = MYST_REGION_KERNEL;
    int fd = -1;
    uint64_t r;
    const void* image_data = (const void*)baseaddr + *vaddr;
    size_t image_size;

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

    if (myst_region_open(context) != 0)
        ERAISE(-EINVAL);

    ECHECK(_load_kernel_pages(context, &_details.kernel.image, *vaddr));

    const uint64_t m = PAGE_SIZE;
    ECHECK(myst_round_up(_details.kernel.image.image_size, m, &r));
    *vaddr += r;

    image_size = r;

    if (myst_region_close(context, name, *vaddr) != 0)
        ERAISE(-EINVAL);

    *(vaddr) += PAGE_SIZE;

    if (baseaddr)
        ECHECK(myst_add_symbol_file_by_path(path, image_data, image_size));

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _add_simple_region(
    myst_region_context_t* context,
    uint64_t* vaddr,
    const char* name,
    const void* data,
    size_t size)
{
    int ret = 0;
    const uint8_t* p = data;
    size_t r = size;
    __attribute__((__aligned__(PAGE_SIZE))) uint8_t page[PAGE_SIZE];
    const int flags = PROT_READ | MYST_REGION_EXTEND;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (myst_region_open(context) != 0)
        ERAISE(-EINVAL);

    /* copy full pages */
    while (r >= PAGE_SIZE)
    {
        memcpy(page, p, PAGE_SIZE);

        if (_add_page(context, *vaddr, page, flags) != 0)
            ERAISE(-EINVAL);

        *vaddr += sizeof(page);
        p += PAGE_SIZE;
        r -= PAGE_SIZE;
    }

    /* copy final partial page */
    if (r)
    {
        memcpy(page, p, r);
        memset(page + r, 0, sizeof(page) - r);

        if (_add_page(context, *vaddr, page, flags) != 0)
            ERAISE(-EINVAL);

        *vaddr += sizeof(page);
    }

    if (myst_region_close(context, name, *vaddr) != 0)
        ERAISE(-EINVAL);

    *(vaddr) += PAGE_SIZE;

done:
    return ret;
}

static int _add_crt_reloc_region(
    myst_region_context_t* context,
    uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_CRT_RELOC,
        _details.crt.image.reloc_data,
        _details.crt.image.reloc_size);
}

static int _add_kernel_reloc_region(
    myst_region_context_t* context,
    uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_KERNEL_RELOC,
        _details.kernel.image.reloc_data,
        _details.kernel.image.reloc_size);
}

static int _add_kernel_symtab_region(
    myst_region_context_t* context,
    uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_KERNEL_SYMTAB,
        _details.kernel.image.symtab_data,
        _details.kernel.image.symtab_size);
}

static int _add_kernel_dynsym_region(
    myst_region_context_t* context,
    uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_KERNEL_DYNSYM,
        _details.kernel.image.dynsym_data,
        _details.kernel.image.dynsym_size);
}

static int _add_kernel_strtab_region(
    myst_region_context_t* context,
    uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_KERNEL_STRTAB,
        _details.kernel.image.strtab_data,
        _details.kernel.image.strtab_size);
}

static int _add_kernel_dynstr_region(
    myst_region_context_t* context,
    uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_KERNEL_DYNSTR,
        _details.kernel.image.dynstr_data,
        _details.kernel.image.dynstr_size);
}

static int _add_rootfs_region(myst_region_context_t* context, uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_ROOTFS,
        _details.rootfs.buffer,
        _details.rootfs.buffer_size);
}

static int _add_archive_region(myst_region_context_t* context, uint64_t* vaddr)
{
    return _add_simple_region(
        context,
        vaddr,
        MYST_REGION_ARCHIVE,
        _details.archive.buffer,
        _details.archive.buffer_size);
}

static int _add_config_region(myst_region_context_t* context, uint64_t* vaddr)
{
    const char name[] = MYST_REGION_CONFIG;

    if (_details.config.buffer == NULL)
        return 0;

    return _add_simple_region(
        context,
        vaddr,
        name,
        _details.config.buffer,
        _details.config.buffer_size);
}

static int _add_mman_region(myst_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    __attribute__((__aligned__(PAGE_SIZE))) uint8_t page[PAGE_SIZE];
    const size_t mman_pages = _details.mman_size / PAGE_SIZE;
    const char name[] = MYST_REGION_MMAN;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (myst_region_open(context) != 0)
        ERAISE(-EINVAL);

    memset(page, 0, sizeof(page));

    /* Add the leading guard page */
    {
        int flags = PROT_NONE | MYST_REGION_EXTEND;

        if (_add_page(context, *vaddr, page, flags) != 0)
            ERAISE(-EINVAL);

        *vaddr += sizeof(page);
    }

    for (size_t i = 0; i < mman_pages; i++)
    {
        int flags = PROT_READ | PROT_WRITE | PROT_EXEC;

        if (_add_page(context, *vaddr, page, flags) != 0)
            ERAISE(-EINVAL);

        *vaddr += sizeof(page);
    }

    /* Add the trailing guard page */
    {
        int flags = PROT_NONE | MYST_REGION_EXTEND;

        if (_add_page(context, *vaddr, page, flags) != 0)
            ERAISE(-EINVAL);

        *vaddr += sizeof(page);
    }

    if (myst_region_close(context, name, *vaddr) != 0)
        ERAISE(-EINVAL);

    *(vaddr) += PAGE_SIZE;

done:
    return ret;
}

oe_result_t oe_load_extra_enclave_data(
    void* arg,
    uint64_t vaddr,
    const void* page,
    uint64_t flags,
    bool extend);

int add_regions(void* arg, uint64_t baseaddr, myst_add_page_t add_page)
{
    myst_region_context_t* context = NULL;
    uint64_t vaddr = 0;

    if (myst_region_init(add_page, arg, &context) != 0)
        _err("myst_region_init() failed");

    if (_add_kernel_region(context, baseaddr, &vaddr) != 0)
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

    if (_add_archive_region(context, &vaddr) != 0)
        _err("_add_archive_region() failed");

    if (_add_mman_region(context, &vaddr) != 0)
        _err("_add_mman_region() failed");

    if (_add_config_region(context, &vaddr) != 0)
        _err("_add_config_region() failed");

    if (myst_region_release(context) != 0)
        _err("myst_region_release() failed");

    return 0;
}
