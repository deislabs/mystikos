// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
    argv[1] = test name
    argv[2] = expected hostname
*/
int test_hostname(int argc, const char* argv[])
{
    int r;
    char hostname[HOST_NAME_MAX];
    char new_hostname[] = "changed";

    assert(argc == 2);

    // Validate application hostname is correct to start with
    assert(gethostname(hostname, sizeof(hostname)) == 0);
    assert(strcmp(hostname, argv[1]) == 0);

    // Change the name
    assert(sethostname(new_hostname, sizeof(new_hostname)) == 0);

    // Validate it was changed correctly
    assert(gethostname(hostname, sizeof(hostname)) == 0);
    assert(strcmp(hostname, new_hostname) == 0);

    printf("=== passed test (%s-hostname-config)\n", argv[0]);

    return 0;
}

int main(int argc, const char* argv[])
{
    assert(test_hostname(argc, argv) == 0);

    return 0;
}
