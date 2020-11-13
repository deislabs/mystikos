// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, const char* argv[], const char* envp[])
{
    for (size_t i = 0; i < argc; i++)
    {
        printf("child: argv[%zu]={%s}\n", i, argv[i]);
        if (i == 0)
            assert(strcmp(argv[i], "/bin/child") == 0);
        else if (i == 1)
            assert(strcmp(argv[i], "arg1") == 0);
        else if (i == 2)
            assert(strcmp(argv[i], "arg2") == 0);
    }

    for (size_t i = 0; envp[i]; i++)
    {
        printf("child: envp[%zu]={%s}\n", i, envp[i]);
        if (i == 0)
            assert(strcmp(envp[i], "X=1") == 0);
        else if (i == 1)
            assert(strcmp(envp[i], "Y=1") == 0);
    }

    /* sleep for 10 milliseconds */
    const uint64_t msec = 10;
    struct timespec req = {.tv_sec = 0, .tv_nsec = msec * 1000000};
    nanosleep(&req, NULL);

    return 123;
}
