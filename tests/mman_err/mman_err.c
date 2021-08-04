// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

/* test unsupported mapping of a fixed address */
void test_unsupported_fixed_addr_mapping(void)
{
    const int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    void* ptr = mmap(NULL, 4096, prot, flags, -1, 0);
    assert(ptr != (void*)-1);
    munmap(ptr, 4096);

    flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
    ptr = mmap(ptr, 4096, prot, flags, -1, 0);
    assert(ptr == (void*)-1);
    /* Mystikos-specific errno */
    assert(errno == EINVAL);
}

void test_oversized_mapping(void)
{
    const size_t length = 4UL * 1024UL * 1024UL * 1024UL; /* 4GB */
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    void* ptr = mmap(NULL, length, prot, flags, -1, 0);
    assert(ptr == (void*)-1);
    assert(errno == ENOMEM);
}

void test_invalid_arguments(void)
{
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE;

    /* negative fd without MAP_ANONYMOUS */
    void* ptr = mmap(NULL, 4096, prot, flags, -1, 0);
    assert(ptr == (void*)-1);
    assert(errno == EBADF);

    /* zero length */
    ptr = mmap(NULL, 0, prot, flags, -1, 0);
    assert(ptr == (void*)-1);
    assert(errno == EINVAL);
}

void test_non_page_aligend_addr(void)
{
    const int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    void* ptr = mmap(NULL, 4096, prot, flags, -1, 0);
    assert(ptr != (void*)-1);
    munmap(ptr, 4096);

    ptr = mmap((void*)(ptr + 1), 4096, prot, flags, -1, 0);
    assert(ptr == (void*)-1);
    assert(errno == EINVAL);
}

void test_non_page_aligned_offset(void)
{
    const int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE;
    int fd = open("/dev/zero", O_RDWR);
    assert(fd > 0);

    void* ptr = mmap(NULL, 4096, prot, flags, fd, 4096);
    assert(ptr != (void*)-1);
    munmap(ptr, 4096);

    ptr = mmap(ptr, 4096, prot, flags, fd, 4096);
    assert(ptr != (void*)-1);
    munmap(ptr, 4096);

    /* Non-null addr */
    ptr = mmap(ptr, 4096, prot, flags, fd, 4097);
    assert(ptr == (void*)-1);
    assert(errno == EINVAL);

    /* null addr */
    ptr = mmap(NULL, 4096, prot, flags, fd, 4097);
    assert(ptr == (void*)-1);
    assert(errno == EINVAL);

    close(fd);
}

int main(int argc, const char* argv[])
{
    test_unsupported_fixed_addr_mapping();
    test_oversized_mapping();
    test_invalid_arguments();
    test_non_page_aligend_addr();
    test_non_page_aligned_offset();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
