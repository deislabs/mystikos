#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>

int main(int argc, const char* argv[])
{
    const uint32_t leaf = 0xC0000000;
    const uint32_t subleaf = 0;
    uint32_t rax = 0;
    uint32_t rbx = 0;
    uint32_t rcx = 0;
    uint32_t rdx = 0;

    __cpuid_count(leaf, subleaf, rax, rbx, rcx, rdx);

    printf("rax=%x rbx=%x rcx=%x rdx=%x\n", rax, rbx, rcx, rdx);

    printf("=== passed tests (%s)\n", argv[0]);

    return 0;
}
