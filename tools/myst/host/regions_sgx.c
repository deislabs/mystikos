#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/regions.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include "regions.h"
#include "utils.h"

/* forward declaration of the OE internal API */
oe_result_t oe_load_extra_enclave_data(
    void* arg,
    uint64_t vaddr,
    const void* page,
    uint64_t flags,
    bool extend);

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

oe_result_t myst_load_extra_enclave_data_hook(void* arg, uint64_t baseaddr)
{
    add_regions(arg, baseaddr, _add_page);
    return OE_OK;
}
