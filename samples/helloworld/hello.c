// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[])
{
    assert(argc == 4);
    assert(strcmp(argv[0], "/bin/hello") == 0);
    assert(strcmp(argv[1], "red") == 0);
    assert(strcmp(argv[2], "green") == 0);
    assert(strcmp(argv[3], "blue") == 0);
    assert(argv[4] == NULL);

    printf("  Hello world!\n  I received: ");
    for (int i = 0; i < argc; i++)
    {
        if (i > 0)
            printf(", ");
        printf("argv[%d]={%s}", i, argv[i]);
    }

    printf("\n=== passed test ==== (%s)\n", argv[0]);

    return 0;
}
