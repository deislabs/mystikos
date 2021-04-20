// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

void test_big_mapping()
{
    size_t length = 8UL * 1024UL * 1024UL * 1024UL;
    const int prot = PROT_NONE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    uint8_t* addr = mmap(NULL, length, prot, flags, -1, 0);
    assert(addr != MAP_FAILED);
    printf("addr=%p\n", addr);
    munmap(addr, length);
}

int main(int argc, const char* argv[])
{
    const size_t PAGE_SIZE = 4096;
    size_t length = 8 * PAGE_SIZE;
    const int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    myst_maps_t* maps;
    int r;

    uint8_t* addr = mmap(NULL, length, prot, flags, -1, 0);
    assert(addr != MAP_FAILED);
    mprotect(addr + 0 * PAGE_SIZE, PAGE_SIZE, PROT_NONE);
    mprotect(addr + 1 * PAGE_SIZE, PAGE_SIZE, PROT_READ);
    mprotect(addr + 2 * PAGE_SIZE, PAGE_SIZE, PROT_WRITE);
    mprotect(addr + 3 * PAGE_SIZE, PAGE_SIZE, PROT_EXEC);
    mprotect(addr + 4 * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(addr + 5 * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_EXEC);
    mprotect(addr + 6 * PAGE_SIZE, PAGE_SIZE, PROT_WRITE | PROT_EXEC);

    if ((r = myst_maps_load(&maps)) != 0)
    {
        fprintf(stderr, "load_maps() failed: errno=%d\n", -r);
        exit(1);
    }

#if 0
    myst_maps_dump(maps);
#endif

    for (size_t i = 0; i < (length / PAGE_SIZE); i++)
    {
        uint8_t* p = addr + (i * PAGE_SIZE);
        struct myst_mstat ms;

        myst_mstat(maps, p, &ms);

#if 0
        myst_mstat_dump(&ms);
#endif

        assert(ms.flags == MAP_PRIVATE);

        switch (i)
        {
            case 0:
                assert(ms.prot == PROT_NONE);
                break;
            case 1:
                assert(ms.prot == PROT_READ);
                break;
            case 2:
                assert(ms.prot == PROT_WRITE);
                break;
            case 3:
                assert(ms.prot == PROT_EXEC);
                break;
            case 4:
                assert(ms.prot == (PROT_READ | PROT_WRITE));
                break;
            case 5:
                assert(ms.prot == (PROT_READ | PROT_EXEC));
                break;
            case 6:
                assert(ms.prot == (PROT_WRITE | PROT_EXEC));
                break;
            case 7:
                assert(ms.prot == (PROT_READ | PROT_WRITE | PROT_EXEC));
                break;
        }
    }

    myst_maps_free(maps);
    munmap(addr, length);

    test_big_mapping();

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
