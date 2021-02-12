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
    argv[2] = expected cwd
*/
int test_spawn_cwd(int argc, const char* argv[])
{
    int r;
    pid_t pid = 0;
    int wstatus;
    char cwdbuf[200];
    char* child_argv1[] = {"/bin/child-cwd", (char*)argv[1], NULL};
    char* child_argv2[] = {"/bin/child-cwd", "/usr", NULL};

    assert(argc == 2);

    // Validate our cwd is correct
    assert(getcwd(cwdbuf, sizeof(cwdbuf)) != NULL);
    assert(strcmp(cwdbuf, argv[1]) == 0);

    assert(
        posix_spawn(&pid, child_argv1[0], NULL, NULL, child_argv1, NULL) == 0);

    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 0);

    // should still be /
    assert(getcwd(cwdbuf, sizeof(cwdbuf)) != 0);
    assert(strcmp(cwdbuf, argv[1]) == 0);

    // Now set it to something else
    assert(chdir("/usr") == 0);

    assert(
        posix_spawn(&pid, child_argv2[0], NULL, NULL, child_argv2, NULL) == 0);

    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 0);

    // should still be /usr
    assert(getcwd(cwdbuf, sizeof(cwdbuf)) != 0);
    assert(strcmp(cwdbuf, "/usr") == 0);

    printf("=== passed test (%s-cwdtest1)\n", argv[0]);

    return 0;
}

int main(int argc, const char* argv[])
{
    assert(test_spawn_cwd(argc, argv) == 0);

    return 0;
}
