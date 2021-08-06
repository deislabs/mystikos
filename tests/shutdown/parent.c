// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

// main parent waits for spawned child to shutdown before exiting
// Child has no SIGGHUP handler
int test1(const char* test_name)
{
    int r;
    pid_t pid = 0;
    char* child_argv[] = {"/bin/child", (char*)test_name, NULL};
    int wstatus;

    r = posix_spawn(&pid, child_argv[0], NULL, NULL, child_argv, NULL);
    if (r != 0)
    {
        printf("r=%d\n", r);
        assert("failed to spawn child" == NULL);
    }
    sleep(1);
    // assert(waitpid(pid, &wstatus, 0) == pid);
    // printf("Passed\n");

    return 0;
}

// main parent waits for spawned child to shutdown before exiting
// Child has SIGGHUP handler
int test2(const char* test_name)
{
    int r;
    pid_t pid = 0;
    char* child_argv[] = {"/bin/child", (char*)test_name, NULL};
    int wstatus;

    r = posix_spawn(&pid, child_argv[0], NULL, NULL, child_argv, NULL);
    if (r != 0)
    {
        assert("failed to spawn child" == NULL);
    }
    sleep(1);

    return 0;
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
}