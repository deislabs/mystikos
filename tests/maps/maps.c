// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <myst/maps.h>

/* read info about the given page from "/proc/self/maps" */
int mstat(const void* addr, int* prot, int* flags)
{
    myst_maps_t* maps;
    struct myst_mstat buf;

    if (myst_maps_load(&maps) != 0)
        return -1;

    if (myst_mstat(maps, addr, &buf) != 0)
        return -1;

    myst_maps_free(maps);

    *prot = buf.prot;
    *flags = buf.flags;
    return 0;
}

int main(int argc, const char* argv[])
{
    const size_t PAGE_SIZE = 4096;
    size_t length = 8 * PAGE_SIZE;
    const int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    /* map 8 pages and give them different protections */
    uint8_t* addr = mmap(NULL, length, prot, flags, -1, 0);
    assert(addr != MAP_FAILED);

    /* set the permissions of the first 7 pages */
    mprotect(addr + 0 * PAGE_SIZE, PAGE_SIZE, PROT_NONE);
    mprotect(addr + 1 * PAGE_SIZE, PAGE_SIZE, PROT_READ);
    mprotect(addr + 2 * PAGE_SIZE, PAGE_SIZE, PROT_WRITE);
    mprotect(addr + 3 * PAGE_SIZE, PAGE_SIZE, PROT_EXEC);
    mprotect(addr + 4 * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(addr + 5 * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_EXEC);
    mprotect(addr + 6 * PAGE_SIZE, PAGE_SIZE, PROT_WRITE | PROT_EXEC);

    /* verify the permissions of the pages */
    for (size_t i = 0; i < (length / PAGE_SIZE); i++)
    {
        uint8_t* p = addr + (i * PAGE_SIZE);
        int mstat_prot;
        int mstat_flags;

        /* get the protection and flags for this page */
        assert(mstat(p, &mstat_prot, &mstat_flags) == 0);

        assert(mstat_flags == MAP_PRIVATE);

        switch (i)
        {
            case 0:
                assert(mstat_prot == PROT_NONE);
                break;
            case 1:
                assert(mstat_prot == PROT_READ);
                break;
            case 2:
                assert(mstat_prot == PROT_WRITE);
                break;
            case 3:
                assert(mstat_prot == PROT_EXEC);
                break;
            case 4:
                assert(mstat_prot == (PROT_READ | PROT_WRITE));
                break;
            case 5:
                assert(mstat_prot == (PROT_READ | PROT_EXEC));
                break;
            case 6:
                assert(mstat_prot == (PROT_WRITE | PROT_EXEC));
                break;
            case 7:
                assert(mstat_prot == (PROT_READ | PROT_WRITE | PROT_EXEC));
                break;
        }
    }

    /* shrink the mapping by one page */
    size_t length2 = length - PAGE_SIZE;
    int mremap_flags = MREMAP_MAYMOVE;
    uint8_t* addr2 = mremap(addr, length, length2, mremap_flags);
    assert(addr2 != MAP_FAILED);

    /* verify that the permissions of the remapped memory have not changed */
    for (size_t i = 0; i < (length2 / PAGE_SIZE); i++)
    {
        uint8_t* p = addr2 + (i * PAGE_SIZE);
        int mstat_prot;
        int mstat_flags;

        /* get the protection and flags for this page */
        assert(mstat(p, &mstat_prot, &mstat_flags) == 0);

        assert(mstat_flags == MAP_PRIVATE);

        switch (i)
        {
            case 0:
                assert(mstat_prot == PROT_NONE);
                break;
            case 1:
                assert(mstat_prot == PROT_READ);
                break;
            case 2:
                assert(mstat_prot == PROT_WRITE);
                break;
            case 3:
                assert(mstat_prot == PROT_EXEC);
                break;
            case 4:
                assert(mstat_prot == (PROT_READ | PROT_WRITE));
                break;
            case 5:
                assert(mstat_prot == (PROT_READ | PROT_EXEC));
                break;
            case 6:
                assert(mstat_prot == (PROT_WRITE | PROT_EXEC));
                break;
        }
    }

    /* without making permission consistent, mremap() fails with EFAULT */
    mprotect(addr, length, PROT_READ | PROT_WRITE | PROT_EXEC);

    /* expand the mapping by two pages */
    size_t length3 = length + PAGE_SIZE;
    uint8_t* addr3 = mremap(addr2, length2, length3, mremap_flags);
    assert(addr3 != MAP_FAILED);

    /* verify permissions of remapped memory (new page will be r-w-x */
    for (size_t i = 0; i < (length3 / PAGE_SIZE); i++)
    {
        uint8_t* p = addr3 + (i * PAGE_SIZE);
        int mstat_prot;
        int mstat_flags;

        assert(mstat(p, &mstat_prot, &mstat_flags) == 0);
        assert(mstat_flags == MAP_PRIVATE);
        assert(mstat_prot == (PROT_READ | PROT_WRITE | PROT_EXEC));
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
