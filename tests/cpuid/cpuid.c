#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>

void test_cpuid()
{
    const uint32_t leaf = 0xC0000000;
    const uint32_t subleaf = 0;
    uint32_t rax = 0;
    uint32_t rbx = 0;
    uint32_t rcx = 0;
    uint32_t rdx = 0;

    __cpuid_count(leaf, subleaf, rax, rbx, rcx, rdx);

#if 0
    printf("rax=%x rbx=%x rcx=%x rdx=%x\n", rax, rbx, rcx, rdx);
#endif
}

int main(int argc, const char* argv[])
{
    test_cpuid();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
