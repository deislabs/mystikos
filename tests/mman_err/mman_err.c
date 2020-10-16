// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <sys/mman.h>
#include <stdio.h>

/* test unsupported mapping of a fixed address */
void test_unsupported_fixed_addr_mapping(void)
{
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    void* ptr = mmap(NULL, 4096, prot, flags, -1, 0);
    assert(ptr != (void*)-1);
    munmap(ptr, 4096);

    ptr = mmap(ptr, 4096, prot, flags, -1, 0);
    assert(ptr == (void*)-1);

}

void test_oversized_mapping(void)
{
    const size_t length = 4UL * 1024UL *  1024UL * 1024UL; /* 4GB */
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    void* ptr = mmap(NULL, length, prot, flags, -1, 0);
    assert(ptr == (void*)-1);

}

int main(int argc, const char* argv[])
{
    test_unsupported_fixed_addr_mapping();
    test_oversized_mapping();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
