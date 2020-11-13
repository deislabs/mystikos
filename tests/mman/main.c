// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>

int main(int argc, const char* argv[])
{
    extern void test_mman(void);

    test_mman();
    printf("passed test (%s)\n", argv[0]);
    return 0;
}
