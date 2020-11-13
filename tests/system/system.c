// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    int r;

    r = system("cmd 10");
    assert(WIFEXITED(r));
    assert(WEXITSTATUS(r) == 10);

    r = system("cmd 20");
    assert(WIFEXITED(r));
    assert(WEXITSTATUS(r) == 20);

    r = system("cmd 30");
    assert(WIFEXITED(r));
    assert(WEXITSTATUS(r) == 99);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
