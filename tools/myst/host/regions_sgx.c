#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/region.h>
#include <openenclave/bits/sgx/sgxextra.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include "regions.h"
#include "utils.h"

void* __image_data;
size_t __image_size;

static int _add_page(void* arg, uint64_t vaddr, const void* page, int flags)
{
    uint64_t oe_flags = SGX_SECINFO_REG;
    bool extend = false;

    if (flags & PROT_READ)
        oe_flags |= SGX_SECINFO_R;

    if (flags & PROT_WRITE)
        oe_flags |= SGX_SECINFO_W;

    if (flags & PROT_EXEC)
        oe_flags |= SGX_SECINFO_X;

    if (flags & MYST_REGION_EXTEND)
        extend = true;

    if (oe_load_extra_enclave_data(arg, vaddr, page, oe_flags, extend) != OE_OK)
    {
        _err("oe_load_extra_enclave_data() failed: vaddr=%lu", vaddr);
        return -EINVAL;
    }

    return 0;
}

static int _add_image_pages(
    void* arg,
    const void* image_data,
    size_t image_size)
{
    int ret = 0;
    const void* regions_end = (const uint8_t*)image_data + image_size;
    myst_region_t region;

    /* find the flags region */
    if (myst_region_find(regions_end, MYST_FLAGS_REGION_NAME, &region) != 0)
        ERAISE(-EINVAL);

    /* add the pages */
    {
        const uint8_t* data = image_data;
        size_t size = image_size;
        const uint8_t* flags = region.data;
        uint64_t vaddr = 0;
        uint64_t index = 0;

        if ((size % PAGE_SIZE) != 0)
            ERAISE(-EINVAL);

        while (size)
        {
            __attribute__((__aligned__(PAGE_SIZE))) uint8_t page[PAGE_SIZE];
            memcpy(page, data, PAGE_SIZE);
            ECHECK(_add_page(arg, vaddr, page, flags[index]));
            vaddr += PAGE_SIZE;
            data += PAGE_SIZE;
            size -= PAGE_SIZE;
            index++;
        }
    }

done:
    return ret;
}

oe_result_t oe_load_extra_enclave_data_hook(void* arg, uint64_t baseaddr)
{
    if (__image_data && __image_size)
    {
        if (_add_image_pages(arg, __image_data, __image_size) != 0)
            _err("_add_image_pages() failed");
    }
    else
    {
        add_regions(arg, baseaddr, _add_page);
    }

    return OE_OK;
}
