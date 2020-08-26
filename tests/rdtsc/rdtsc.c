#include <stdio.h>
#include <stdint.h>
#include <assert.h>

uint64_t rdtsc(void)
{
    uint32_t hi;
    uint32_t lo;

    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32 | (uint64_t)lo);
}

int main(int argc, const char* argv[])
{
    uint64_t x1 = rdtsc();
    uint64_t x2 = rdtsc();

    printf("x1=%lu\n", x1);
    printf("x2=%lu\n", x2);

    assert(x2 >= x1);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
