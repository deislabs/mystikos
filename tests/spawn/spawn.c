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

int test_spawn1(int argc, const char* argv[])
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

static _Atomic(int) sigtest1_usr1 = 0;
static _Atomic(int) sig_handler_chld = 0;
void test_spawn_sig_handler(int signo)
{
    switch (signo)
    {
        case SIGCHLD:
            sig_handler_chld = 1;
            break;
        case SIGUSR1:
            sigtest1_usr1 = 1;
            break;
        default:
            assert(0);
    }
}

int test_spawn_sig(int argc, const char* argv[])
{
    int r;
    pid_t pid = 0;
    char* const child_argv[] = {"/bin/child-signal", "sigtest1", NULL};
    char* const child_envp[] = {"X=1", "Y=1", NULL};
    int wstatus;

    assert(sigtest1_usr1 == 0);
    assert(signal(SIGUSR1, test_spawn_sig_handler) == 0);

    assert(sig_handler_chld == 0);
    assert(signal(SIGCHLD, test_spawn_sig_handler) == 0);

    r = posix_spawn(&pid, child_argv[0], NULL, NULL, child_argv, child_envp);

    if (r != 0)
    {
        printf("r=%d\n", r);
        assert(0);
    }

    // Wait until we know the process is up
    int iteration = 0;
    while ((sigtest1_usr1 == 0) && (iteration < 1000))
    {
        const uint64_t msec = 10;
        struct timespec req = {.tv_sec = 0, .tv_nsec = msec * 1000000};
        nanosleep(&req, NULL);
        iteration++;
    }

    // validate we got the SIGUSR1
    assert(sigtest1_usr1 == 1);

    // Now send a signal to the child
    assert(kill(pid, SIGUSR1) == 0);

    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 0);

    // validate we got the SIGCHLD
    assert(sig_handler_chld == 1);

    printf("=== passed test (%s-sigtest1)\n", argv[0]);

    return 0;
}

int main(int argc, const char* argv[])
{
    assert(test_spawn1(argc, argv) == 0);

    assert(test_spawn_sig(argc, argv) == 0);

    return 0;
}
