#include <myst/errno.h>
#include <myst/regions.h>
#include <openenclave/bits/sgx/sgxextra.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include "regions.h"
#include "utils.h"

static int _add_page(
    uint64_t vaddr,
    const void* page,
    int prot,
    int flags,
    void* arg)
{
    uint64_t oe_flags = SGX_SECINFO_REG;
    bool extend = (flags & MYST_REGION_EXTEND);

    if (prot & PROT_READ)
        oe_flags |= SGX_SECINFO_R;

    if (prot & PROT_WRITE)
        oe_flags |= SGX_SECINFO_W;

    if (prot & PROT_EXEC)
        oe_flags |= SGX_SECINFO_X;

    if (oe_load_extra_enclave_data(arg, vaddr, page, oe_flags, extend) != OE_OK)
    {
        _err("oe_load_extra_enclave_data() failed: vaddr=%lu", vaddr);
        return -EINVAL;
    }

    return 0;
}

oe_result_t oe_load_extra_enclave_data_hook(void* arg, uint64_t baseaddr)
{
    add_regions(arg, baseaddr, _add_page);
    return OE_OK;
}
