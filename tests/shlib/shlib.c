// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#define MAGIC 0xc72a0eae2f4a4003

int main(int argc, const char* argv[])
{
    extern uint64_t foo();

    uint64_t magic = foo();

    assert(magic == MAGIC);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}

uint64_t goo()
{
    return MAGIC;
}
