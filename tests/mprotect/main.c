// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    const size_t PAGE_SIZE = 4096;
    size_t length = 8 * PAGE_SIZE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    uint8_t data = 0;

    /* map 8 pages and give them different protections */
    uint8_t* addr = mmap(NULL, length, PROT_NONE, flags, -1, 0);
    assert(addr != MAP_FAILED);

    if (mprotect(addr, length, PROT_READ))
    {
        printf("Error - mprotect(R) failed unexpectedly\n");
        assert(0);
    }
    if (mprotect(addr, length, PROT_WRITE))
    {
        printf("Error - mprotect(W) failed unexpectedly\n");
        assert(0);
    }
    if (mprotect(addr, length, PROT_READ | PROT_WRITE))
    {
        printf("Error - mprotect(R/W) failed unexpectedly\n");
        assert(0);
    }
    if (mprotect(addr, length, PROT_READ | PROT_EXEC))
    {
        printf("Error - mprotect(R/X) failed unexpectedly\n");
        assert(0);
    }
    if (mprotect(addr, length, PROT_READ | PROT_WRITE | PROT_EXEC))
    {
        printf("Error - mprotect(R/W/X) failed unexpectedly\n");
        assert(0);
    }
    if (!mprotect(addr, length, 0xFF))
    {
        printf("Error - mprotect didn't reject invalid PROT bits\n");
        assert(0);
    }
    if (!mprotect(0, length, PROT_READ | PROT_WRITE))
    {
        printf("Error - mprotect() didn't reject invalid addr\n");
        assert(0);
    }
    if (!mprotect(addr, 0, PROT_READ | PROT_WRITE))
    {
        printf("Error - mprotect() didn't reject invalid length\n");
        assert(0);
    }
    for (size_t i = 0; i < length; i++)
    {
        data = addr[i];
    }
    printf("R/W/X PAGES: all pages readable as expected\n");
    for (size_t i = 0; i < length; i++)
    {
        addr[i] = 0;
    }
    printf("R/W/X PAGES: all pages writable as expected\n");
    mprotect(addr, length, PROT_READ);
    for (size_t i = 0; i < length; i++)
    {
        data = addr[i];
    }
    printf("R/O PAGES: all pages readable as expected\n");
    if (mprotect(addr, length, PROT_NONE))
    {
        printf("Error - mprotect(NONE) failed unexpectedly\n");
        assert(0);
    }
    data = addr[0];
    /* not expected to reach here */
    printf("ERROR - No Access PAGES: first byte readable\n");
    return 0;
}