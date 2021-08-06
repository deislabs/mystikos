// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile int _sighup_count = 0;

void signal_handler(int signo)
{
    assert(signo == SIGHUP);
    _sighup_count++;
}

int test1(const char* test_name)
{
    sleep(3);
}

int test2(const char* test_name)
{
    assert(signal(SIGHUP, signal_handler) == 0);
    sleep(3);
    assert(_sighup_count == 1);
    printf("SIGHUP was intercepted\n");
}

int main(int argc, const char* argv[])
{
    assert(argc == 2);
    printf("hello from %s %s\n", argv[0], argv[1]);

    if (strcmp("parent-wait-child-spawn-exit-no-sighup-handler", argv[1]) == 0)
        test1(argv[1]);
    else if (
        strcmp("parent-wait-child-spawn-exit-with-sighup-handler", argv[1]) ==
        0)
        test2(argv[1]);
    else
        assert("invalid option" == NULL);

    printf("goodbye from %s %s\n", argv[0], argv[1]);
    return 0;
}