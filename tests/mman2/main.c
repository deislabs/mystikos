// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
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

#define SIZE (128 * 1024 * 1024)

struct mapping
{
    void* addr;
    size_t length;
};

void test1(void)
{
    void* data;
    const size_t size = SIZE;
    struct mapping* mappings;
    const size_t max_mappings = size / PAGE_SIZE;
    size_t nmappings = 0;
    size_t total_length = 0;
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    if (!(mappings = malloc(max_mappings * sizeof(struct mapping))))
        assert(0);

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    // memset(data, 0, size);

    // printf("pages=%zu\n", size / PAGE_SIZE);
    assert(myst_mman2_init(data, size) == 0);

    void* prev = NULL;

    //==========================================================================
    //
    // Perform mappings:
    //
    //==========================================================================

    for (size_t i = 0; i < max_mappings; i++)
    {
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

    //==========================================================================
    //
    // Release all the mappings
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        void* addr = mappings[i].addr;
        size_t length = mappings[i].length;
        assert(myst_mman2_munmap(addr, length) == 0);
    }

    // printf("free_bits: %zu\n", myst_mman2_count_free_bits());
    assert(myst_mman2_count_free_bits() == total_length / PAGE_SIZE);

    //==========================================================================
    //
    // Perform mappings again:
    //
    //==========================================================================

    prev = NULL;
    nmappings = 0;
    total_length = 0;

    for (size_t i = 0; i < max_mappings; i++)
    {
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
    assert(myst_mman2_count_free_bits() == 0);

    //==========================================================================
    //
    // Release only odd mappings:
    //
    //==========================================================================

    assert(myst_mman2_count_free_bits() == 0);
    size_t free_bits = 0;

    for (size_t i = 0; i < nmappings; i++)
    {
        if (i % 2 == 0)
            continue;

        void* addr = mappings[i].addr;
        size_t length = mappings[i].length;
        assert(myst_mman2_munmap(addr, length) == 0);
        total_length -= length;
        free_bits++;
        memset(&mappings[i], 0, sizeof(struct mapping));
    }

    assert(myst_mman2_count_free_bits() == free_bits);
    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);

    //==========================================================================
    //
    // Perform odd mappings again but in reverse order:
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        if (i % 2 == 0)
            continue;

        void* ptr;
        const size_t length = PAGE_SIZE;

        int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr);
        assert(ret == 0);
        assert(ptr != MAP_FAILED);

        mappings[i].addr = ptr;
        mappings[i].length = length;
        total_length += length;
    }

    assert(myst_mman2_count_free_bits() == 0);
    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);

    //==========================================================================
    //
    // Release all the mappings
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        void* addr = mappings[i].addr;
        size_t length = mappings[i].length;
        assert(myst_mman2_munmap(addr, length) == 0);
    }

    assert(myst_mman2_count_used_bits() == 0);
    assert(myst_mman2_count_free_bits() == total_length / PAGE_SIZE);

    myst_mman2_release();

    free(mappings);
    free(data);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test2(void)
{
    void* data;
    const size_t size = SIZE;
    struct mapping* mappings;
    const size_t max_mappings = size / PAGE_SIZE;
    size_t nmappings = 0;
    size_t total_length = 0;
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    if (!(mappings = malloc(max_mappings * sizeof(struct mapping))))
        assert(0);

    memset(mappings, 0, max_mappings * sizeof(struct mapping));

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    // memset(data, 0, size);

    assert(myst_mman2_init(data, size) == 0);

    //==========================================================================
    //
    // Perform mappings:
    //
    //==========================================================================

    for (size_t i = 0; i < max_mappings; i++)
    {
        const size_t length = (i + 1) * PAGE_SIZE;
        void* ptr;

        int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr);

        if (ret == -ENOMEM)
            break;

        assert(ptr != MAP_FAILED);

        mappings[nmappings].addr = ptr;
        mappings[nmappings].length = length;
        nmappings++;
        total_length += length;
    }

    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);
    size_t original_length = total_length;
    size_t original_free_bits = myst_mman2_count_free_bits();

    //==========================================================================
    //
    // Release only odd mappings:
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        if (i % 2 == 0)
            continue;

        void* addr = mappings[i].addr;
        size_t length = mappings[i].length;
        assert(myst_mman2_munmap(addr, length) == 0);
        total_length -= length;
        memset(&mappings[i], 0, sizeof(struct mapping));
        // printf("unmap index=%zu length=%zu\n", i, length);
    }

    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);

    //==========================================================================
    //
    // Perform the odd mappings again but in reverse order:
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        size_t index = (nmappings - i - 1);

        if (index % 2 == 0)
            continue;

        const size_t length = (index + 1) * PAGE_SIZE;
        void* ptr;

        // printf("map index=%zu length=%zu\n", index, length);
        int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr);

        if (ret == -ENOMEM)
            break;

        assert(ptr != MAP_FAILED);

        mappings[index].addr = ptr;
        mappings[index].length = length;
        total_length += length;
    }

    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);
    assert(total_length == original_length);
    assert(original_free_bits == myst_mman2_count_free_bits());

    myst_mman2_release();

    free(mappings);
    free(data);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test3(void)
{
    void* data;
    const size_t size = SIZE;
    struct mapping* mappings;
    const size_t max_mappings = size / PAGE_SIZE;
    size_t nmappings = 0;
    size_t total_length = 0;
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    if (!(mappings = malloc(max_mappings * sizeof(struct mapping))))
        assert(0);

    memset(mappings, 0, max_mappings * sizeof(struct mapping));

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    // memset(data, 0, size);

    assert(myst_mman2_init(data, size) == 0);

    //==========================================================================
    //
    // Perform mappings:
    //
    //==========================================================================

    for (size_t i = 0; i < max_mappings; i++)
    {
        const size_t length = size / 8;
        void* ptr;

        int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr);

        if (ret == -ENOMEM)
            break;

        assert(ptr != MAP_FAILED);

        mappings[nmappings].addr = ptr;
        mappings[nmappings].length = length;
        nmappings++;
        total_length += length;
    }

    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);
    size_t original_length = total_length;
    size_t original_free_bits = myst_mman2_count_free_bits();

    //==========================================================================
    //
    // Release only odd mappings:
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        if (i % 2 == 0)
            continue;

        void* addr = mappings[i].addr;
        size_t length = mappings[i].length;
        assert(myst_mman2_munmap(addr, length) == 0);
        total_length -= length;
        memset(&mappings[i], 0, sizeof(struct mapping));
        // printf("unmap index=%zu length=%zu\n", i, length);
    }

    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);

    //==========================================================================
    //
    // Perform the odd mappings again
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        if (i % 2 == 0)
            continue;

        const size_t length = size / 8;
        void* ptr;

        int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr);

        if (ret == -ENOMEM)
            break;

        assert(ptr != MAP_FAILED);

        mappings[i].addr = ptr;
        mappings[i].length = length;
        total_length += length;
    }

    assert(myst_mman2_count_used_bits() == total_length / PAGE_SIZE);
    assert(total_length == original_length);
    assert(original_free_bits == myst_mman2_count_free_bits());

    //==========================================================================
    //
    // Release all mappings
    //
    //==========================================================================

    for (size_t i = 0; i < nmappings; i++)
    {
        void* addr = mappings[i].addr;
        size_t length = mappings[i].length;
        assert(myst_mman2_munmap(addr, length) == 0);
        total_length -= length;
        memset(&mappings[i], 0, sizeof(struct mapping));
    }

    assert(myst_mman2_count_used_bits() == 0);

    myst_mman2_release();

    free(mappings);
    free(data);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test4(void)
{
    void* data;
    const size_t size = SIZE;
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    const size_t max_mappings = 8;
    struct mapping mappings[max_mappings];
    size_t nmappings = 0;

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    assert(myst_mman2_init(data, size) == 0);

    //==========================================================================
    //
    // Perform mappings:
    //
    //     [mmmmmmmm]
    //
    //==========================================================================

    for (size_t i = 0; i < max_mappings; i++)
    {
        const size_t length = PAGE_SIZE;
        void* ptr;

        int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &ptr);
        assert(ret == 0);
        assert(ptr != MAP_FAILED);

        mappings[i].addr = ptr;
        mappings[i].length = length;
        nmappings++;
    }

    //==========================================================================
    //
    // unmap the second and third mappings
    //
    //     [m.m.mmmm]
    //
    //==========================================================================

    assert(myst_mman2_munmap(mappings[1].addr, mappings[1].length) == 0);
    assert(myst_mman2_munmap(mappings[3].addr, mappings[3].length) == 0);

    //==========================================================================
    //
    // Perform in-place remapping:
    //
    //     [mmm.mmmm]
    //
    //==========================================================================

    {
        void* addr;
        const size_t old_size = PAGE_SIZE;
        const size_t new_size = 2 * PAGE_SIZE;
        const int rflags = 0;
        assert(
            myst_mman2_mremap(
                mappings[0].addr, old_size, new_size, rflags, NULL, &addr) ==
            0);
        assert(addr != MAP_FAILED);
        assert(addr == mappings[0].addr);
    }

    //==========================================================================
    //
    // shrink the first mapping:
    //
    //     [m.m.mmmm]
    //
    //==========================================================================

    /* double the size of the first mapping */
    {
        void* addr;
        const size_t old_size = 2 * PAGE_SIZE;
        const size_t new_size = PAGE_SIZE;
        const int rflags = 0;
        assert(
            myst_mman2_mremap(
                mappings[0].addr, old_size, new_size, rflags, NULL, &addr) ==
            0);
        assert(addr != MAP_FAILED);
        assert(addr == mappings[0].addr);
    }

    /* verify that the mapping shrunk by obtaining the page after */
    {
        void* addr;
        const size_t length = PAGE_SIZE;
        assert(myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &addr) == 0);
        assert(addr != MAP_FAILED);
        assert(addr == mappings[0].addr + PAGE_SIZE);
        assert(myst_mman2_munmap(addr, length) == 0);
    }

    //==========================================================================
    //
    // expand the first mapping (not in place)
    //
    //     [..m.mmmmmmm]
    //
    //==========================================================================

    /* triple the size of the first mapping */
    {
        void* addr;
        const size_t old_size = PAGE_SIZE;
        const size_t new_size = 3 * PAGE_SIZE;
        const int rflags = MREMAP_MAYMOVE;
        assert(
            myst_mman2_mremap(
                mappings[0].addr, old_size, new_size, rflags, NULL, &addr) ==
            0);
        assert(addr != MAP_FAILED);
        assert(addr != mappings[0].addr);
    }

    //==========================================================================
    //
    // remap a non-existent mapping
    //
    //     [..m.mmmmmmm]
    //
    //==========================================================================

    /* triple the size of the first mapping */
    {
        void* addr;
        const size_t old_size = PAGE_SIZE;
        const size_t new_size = 2 * PAGE_SIZE;
        const int rflags = MREMAP_MAYMOVE;
        assert(
            myst_mman2_mremap(
                mappings[0].addr, old_size, new_size, rflags, NULL, &addr) ==
            -EPERM);
        assert(addr == MAP_FAILED);
    }

    (void)mappings;

    myst_mman2_release();
    free(data);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test5(void)
{
    void* data;
    size_t length = PAGE_SIZE;
    const size_t size = SIZE;
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    void* addr;
    const size_t n = 1024;

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    assert(myst_mman2_init(data, size) == 0);

    /* map one page */
    int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &addr);
    assert(ret == 0);
    assert(addr != MAP_FAILED);

    /* double the mapping over and over */
    for (size_t i = 0; i < n; i++)
    {
        for (;;)
        {
            const size_t old_size = length;
            const size_t new_size = 2 * length;
            const int rflags = MREMAP_MAYMOVE;

            if (new_size >= myst_mman2_get_usable_size())
            {
                assert(myst_mman2_munmap(addr, old_size) == 0);
                break;
            }

            assert(
                myst_mman2_mremap(
                    addr, old_size, new_size, rflags, NULL, &addr) == 0);
            assert(addr != MAP_FAILED);
            length = new_size;
        }
    }

    myst_mman2_release();
    free(data);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test6(void)
{
    void* data;
    size_t length = 8 * PAGE_SIZE;
    const size_t size = SIZE;
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    void* addr;

    if (!(data = memalign(PAGE_SIZE, size)))
        assert(0);

    assert(myst_mman2_init(data, size) == 0);

    /* map 8 pages */
    int ret = myst_mman2_mmap(NULL, length, prot, flags, -1, 0, &addr);
    assert(ret == 0);
    assert(addr != MAP_FAILED);

    /* mprotect the pages */
    ret = myst_mman2_mprotect(addr, length, PROT_READ);
    assert(myst_mman2_mprotect(addr, length, PROT_READ) == 0);
    assert(myst_mman2_mprotect_stat(addr) == PROT_READ);
    assert(myst_mman2_mprotect(addr, length, prot) == 0);
    assert(myst_mman2_mprotect(addr, 2 * length, prot) == -ENOMEM);
    assert(myst_mman2_munmap(addr, length) == 0);
    assert(myst_mman2_mprotect(addr, length, prot) == -ENOMEM);

    myst_mman2_release();
    free(data);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    test1();
    test2();
    test3();
    test4();
    test5();
    test6();

    printf("=== passed all tests (%s)\n", argv[0]);
    return 0;
}
