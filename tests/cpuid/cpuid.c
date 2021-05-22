// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>

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

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
