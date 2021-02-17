// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int cwdtest1()
{
    return 0;
}

int main(int argc, const char* argv[], const char* envp[])
{
    char cwdbuf[200];

    assert(argc == 2);

    // Validate our cwd is the same as the passed in argv[2]
    assert(getcwd(cwdbuf, sizeof(cwdbuf)) != NULL);
    assert(strcmp(cwdbuf, argv[1]) == 0);

    // Now set our cwd to see if it affects the parent
    assert(chdir("/tmp") == 0);

    // validate it set properly
    assert(getcwd(cwdbuf, sizeof(cwdbuf)) != NULL);
    assert(strcmp(cwdbuf, "/tmp") == 0);
    return 0;
}
