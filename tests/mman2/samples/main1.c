#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

int main()
{
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    size_t length = 8 * PAGE_SIZE;

    /* allocate 8 pages */
    uint8_t* addr = mmap(NULL, length, prot, flags, -1, 0);
    assert(addr != MAP_FAILED);

    /* release half of the mapping ensuring stationary mremap will succeed */
    length /= 2;
    assert(munmap(addr + length, length) == 0);

    /* try growing the mapping with room left on the right */
    size_t old_size = length;
    size_t new_size = old_size * 2;
    uint8_t* new = mremap(addr, old_size, new_size, 0); // MREMAP_MAYMOVE);
    assert(new != MAP_FAILED);

    return 0;
}
