#include <stdio.h>
#include <stdint.h>

int main(int argc, const char* argv[])
{
    uint32_t hi;
    uint32_t lo;

    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));

    printf("rdtsc=%lu\n", ((uint64_t)hi << 32 | (uint64_t)lo));

    return 0;
}
