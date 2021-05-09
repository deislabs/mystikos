// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <myst/mman2.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define NUM_PAGES 1024

int main(int argc, const char* argv[])
{
    void* data;
    const size_t size = PAGE_SIZE * 1024 * 64;

    printf("=== passed test (%s)\n", argv[0]);

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    assert(myst_mman2_init(data, size) == 0);

    for (size_t i = 0; i < 4; i++)
    {
        const int prot = PROT_READ | PROT_WRITE;
        const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        const size_t length = 4 * PAGE_SIZE;
        void* ptr;
        assert(myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr) == 0);
        assert(ptr != MAP_FAILED);

        assert(myst_mman2_munmap(ptr, length) == 0);
    }

    return 0;
}
