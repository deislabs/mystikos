// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
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

struct mapping
{
    void* addr;
    size_t length;
};

int main(int argc, const char* argv[])
{
    void* data;
    const size_t size = 128 * 1024 * 1024;
    struct mapping* mappings;
    const size_t max_mappings = size / PAGE_SIZE;
    size_t nmappings = 0;
    size_t total_length = 0;

    printf("=== passed test (%s)\n", argv[0]);

    if (!(mappings = malloc(max_mappings * sizeof(struct mapping))))
        assert(0);

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    memset(data, 0, size);

    printf("pages=%zu\n", size / PAGE_SIZE);
    assert(myst_mman2_init(data, size) == 0);

    void* prev = NULL;

    for (size_t i = 0; i < max_mappings; i++)
    {
        const int prot = PROT_READ | PROT_WRITE;
        const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        // const size_t length = (i + 1) * PAGE_SIZE;
        const size_t length = PAGE_SIZE;
        void* ptr;

        int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr);

        if (ret == -ENOMEM)
            break;

        assert(ptr != MAP_FAILED);

        if (prev)
        {
            const size_t diff = (size_t)ptr - (size_t)prev;
            assert(diff == length);
        }

        mappings[nmappings].addr = ptr;
        mappings[nmappings].length = length;
        nmappings++;
        total_length += length;

        prev = ptr;
    }

    assert(total_length < size);
    assert(total_length == myst_mman2_get_usable_size());
    // printf("free bits: %zu\n", myst_mman2_count_free_bits());
    assert(myst_mman2_count_free_bits() == 0);

    /* release all the mappings */
    for (size_t i = 0; i < nmappings; i++)
    {
        void* addr = mappings[i].addr;
        size_t length = mappings[i].length;

#if 0
        printf("inside: i=%zu addr=%p length=%zu\n", i, addr, length);
        fflush(stdout);
#endif
        assert(myst_mman2_munmap(addr, length) == 0);
    }

    // printf("free_bits: %zu\n", myst_mman2_count_free_bits());
    assert(myst_mman2_count_free_bits() == total_length / PAGE_SIZE);

    return 0;
}
