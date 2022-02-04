// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    char buf[PATH_MAX];

    getcwd(buf, sizeof(buf));
    assert(strcmp(buf, "/") == 0);

    for (size_t i = 1; i < 10000; i++)
    {
        malloc(i);
    }

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
