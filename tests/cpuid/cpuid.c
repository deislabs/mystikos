// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SGX_TARGET "sgx"

static int is_sgx_target()
{
    char* target = getenv("MYST_TARGET");
    if (target != NULL && !strcmp(SGX_TARGET, target))
        return 1;
    else
        return 0;
}

void test_cpuid(uint32_t leaf, uint32_t subleaf)
{
    uint32_t rax = 0;
    uint32_t rbx = 0;
    uint32_t rcx = 0;
    uint32_t rdx = 0;

    __cpuid_count(leaf, subleaf, rax, rbx, rcx, rdx);

    printf(
        "cpuid(%x, %x): rax=%x rbx=%x rcx=%x rdx=%x\n",
        leaf,
        subleaf,
        rax,
        rbx,
        rcx,
        rdx);

    // For sgx target, check xsave size returned is fixed value 4096
    if (is_sgx_target() && leaf == 0xd && subleaf == 0)
    {
        assert(rbx == 4096);
        assert(rcx == 4096);
    }
}

int main(int argc, const char* argv[])
{
    test_cpuid(0, 0);
    test_cpuid(0x80000001, 0);
    test_cpuid(1, 0x121);
    test_cpuid(7, 0);
    test_cpuid(1, 0);
    test_cpuid(0, 0);
    test_cpuid(11, 0);
    test_cpuid(11, 1);
    test_cpuid(4, 0);
    test_cpuid(4, 1);
    test_cpuid(4, 2);
    test_cpuid(4, 3);
    test_cpuid(4, 4);
    test_cpuid(0x80000000, 0);
    test_cpuid(2, 4167054552);
    test_cpuid(1979933441, 0);
    test_cpuid(0xd, 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
