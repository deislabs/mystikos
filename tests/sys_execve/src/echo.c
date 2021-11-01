// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>

// A very simple echo implementation, used to verify if SYS_execve works
int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        printf("%s ", argv[i]);
    }

    printf("\n");
    return 0;
}
