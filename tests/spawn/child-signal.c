// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static volatile int sigtest1_usr1 = 0;

void sigtest1_handler(int signo)
{
    sigtest1_usr1 = 1;
}

// test is expecting a SIGUSR1 from parent
int sigtest1()
{
    assert(sigtest1_usr1 == 0);
    assert(signal(SIGUSR1, sigtest1_handler) == 0);

    assert(kill(getppid(), SIGUSR1) == 0);

    int iteration = 0;
    while (sigtest1_usr1 != 1 && (iteration < 1000))
    {
        const uint64_t msec = 10;
        struct timespec req = {.tv_sec = 0, .tv_nsec = msec * 1000000};
        nanosleep(&req, NULL);
        iteration++;
    }

    // we should have the SIGUSR1 from the parent by now
    assert(sigtest1_usr1 == 1);

    return 0;
}

int main(int argc, const char* argv[], const char* envp[])
{
    if ((argc = 2) && (strcmp(argv[1], "sigtest1") == 0))
    {
        assert(sigtest1() == 0);
    }
    else
    {
        assert(0);
    }
    return 0;
}
