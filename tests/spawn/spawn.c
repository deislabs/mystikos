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
    pid_t pid = 0;
    char* const child_argv[] = {"/bin/child", "arg1", "arg2", NULL};
    char* const child_envp[] = {"X=1", "Y=1", NULL};
    int wstatus;
    posix_spawnattr_t attr;

    assert(posix_spawnattr_init(&attr) == 0);

    /* POSIX_SPAWN_RESETIDS */
    assert(posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS) == 0);

    /* POSIX_SPAWN_SETSIGMASK */
    {
        sigset_t mask;
        sigfillset(&mask);
        assert(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK) == 0);
        assert(posix_spawnattr_setsigmask(&attr, &mask) == 0);
    }

    r = posix_spawn(&pid, "/bin/child", NULL, &attr, child_argv, child_envp);

    if (r != 0)
    {
        printf("r=%d\n", r);
        assert(0);
    }

    assert(posix_spawnattr_destroy(&attr) == 0);

    assert(waitpid(pid, &wstatus, WNOHANG) == 0);
    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 123);

    printf("parent: pid %d\n", pid);
    printf("parent: exit status: %d\n", WEXITSTATUS(wstatus));

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
