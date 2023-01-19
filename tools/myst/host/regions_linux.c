#include <stdio.h>
#include <sys/mman.h>

#include <myst/errno.h>
#include <myst/regions.h>
#include "regions.h"
#include "utils.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct arg
{
    uint64_t baseaddr;
    uint64_t vaddr;
};

static int _add_page(void* arg_, uint64_t vaddr, const void* page, int flags)
{
    struct arg* arg = (struct arg*)arg_;

    if (vaddr < arg->vaddr)
        _err("_add_page() failed");

    if (arg->baseaddr != 0)
    {
        void* addr = (void*)arg->baseaddr + vaddr;
        int prot = flags & ~MYST_REGION_EXTEND;

        memcpy(addr, page, PAGE_SIZE);

        if (mprotect(addr, PAGE_SIZE, prot) != 0)
            _err("failed to protect memory region");
    }

    arg->vaddr = vaddr + PAGE_SIZE;

    return 0;
}

int map_regions(void** addr_out, size_t* length_out)
{
    int ret = 0;
    void* addr = NULL;
    size_t length;

    if (addr_out)
        *addr_out = NULL;

    if (length_out)
        *length_out = 0;

    if (!addr_out || !length_out)
    {
        ret = -EINVAL;
        goto done;
    }

    /* first determine the size of the regions */
    {
        const uint64_t baseaddr = 0;

        struct arg arg = {.baseaddr = baseaddr, .vaddr = 0};

        if (add_regions(&arg, baseaddr, _add_page) != 0)
        {
            ret = -EINVAL;
            goto done;
        }

        length = arg.vaddr;
    }

    /* create the memory mapping */
    {
        int prot = PROT_READ | PROT_WRITE;
        int flags = MAP_ANONYMOUS | MAP_PRIVATE;

        if ((addr = mmap(NULL, length, prot, flags, -1, 0)) == MAP_FAILED)
            _err("failed to map %zu bytes of memory", length);
    }

    /* map the regions onto the memory mapping */
    {
        const uint64_t baseaddr = (uint64_t)addr;

        struct arg arg = {.baseaddr = baseaddr, .vaddr = 0};

        if (add_regions(&arg, baseaddr, _add_page) != 0)
        {
            ret = -EINVAL;
            goto done;
        }

        if (arg.vaddr != length)
            _err("unexpected mismatch in memory mapping");
    }

    *addr_out = addr;
    *length_out = length;

done:
    return ret;
}
