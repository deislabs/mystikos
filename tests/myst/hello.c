// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>

int main(int argc, const char* argv[], const char* envp[])
{
    printf("\n");

    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);

    printf("\n");

    for (int i = 0; envp[i] != NULL; i++)
        printf("envp[%d]=%s\n", i, envp[i]);

    printf("\n");

    printf("=== Hello World!\n\n");

    return 0;
}
