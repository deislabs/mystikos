// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
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

// main parent waits for forked child to shutdown before exiting
// Child has no SIGGHUP handler
int test3(const char* test_name)
{
    int r;
    pid_t pid = 0;
    char* child_argv[] = {"/bin/child", (char*)test_name, NULL};
    int wstatus;

    pid = fork();
    if (pid > 0)
    {
        printf("Hello from parent %s\n", test_name);
        sleep(1);
        printf("goodbye from parent %s\n", test_name);
    }
    else if (pid == 0)
    {
        printf("Hello from child %s\n", test_name);
        sleep(3);
        printf("goodbye from child %s\n", test_name);
        _Exit(0);
    }
    else
    {
        assert("Fork failed...forgot fork config?" == NULL);
    }
    return 0;
}

// main parent waits for forked child to shutdown before exiting
// Child has SIGGHUP handler

static volatile int _sighup_count = 0;
void signal_handler(int signo)
{
    assert(signo == SIGHUP);
    _sighup_count++;
}

int test4(const char* test_name)
{
    int r;
    pid_t pid = 0;
    char* child_argv[] = {"/bin/child", (char*)test_name, NULL};
    int wstatus;

    pid = fork();
    if (pid > 0)
    {
        printf("Hello from parent %s\n", test_name);
        sleep(1);
        printf("goodbye from parent %s\n", test_name);
    }
    else if (pid == 0)
    {
        assert(signal(SIGHUP, signal_handler) == 0);
        printf("Hello from child %s\n", test_name);
        sleep(3);
        assert(_sighup_count == 1);
        printf("goodbye from child %s\n", test_name);
        _Exit(0);
    }
    else
    {
        assert("Fork failed...forgot fork config?" == NULL);
    }
    return 0;
}

// main parent waits for spawned child to shutdown before exiting
// Child has no SIGGHUP handler
// Child throws an assert on a child thread

static void* _test5_thread_assert(void* arg)
{
    printf("hello from asserting thread\n");
    assert(0);
    return NULL;
}

int test5(const char* test_name)
{
    int r;
    pid_t pid = 0;
    char* child_argv[] = {"/bin/child", (char*)test_name, NULL};
    int wstatus;

    r = fork();
    if (r < 0)
    {
        printf("r=%d\n", r);
        assert("failed to fork child" == NULL);
    }
    else if (r == 0)
    {
        pthread_t thread;
        int r;

        printf("=== start test (%s)\n", __FUNCTION__);

        if ((r = pthread_create(&thread, NULL, _test5_thread_assert, NULL)))
        {
            printf("pthread_create() failed: %d", r);
            abort();
        }

        if (pthread_join(thread, NULL) != 0)
        {
            printf("pthread_join() failed");
            abort();
        }
    }
    else
    {
        int wstate = 0;
        r = waitpid(r, &wstate, 0);
        assert(r > 0);
        assert(WTERMSIG(wstate));
        assert(WTERMSIG(wstate) == SIGABRT);
    }
    return 0;
}

// main parent waits for spawned child to shutdown before exiting
// Child has no SIGGHUP handler
// Child throws an SEGV on a child thread
static void* _test6_thread_assert(void* arg)
{
    printf("hello from crashing thread\n");
    char* crash = NULL;
    crash[0] = 'a';
    return NULL;
}

int test6(const char* test_name)
{
    int r;
    pid_t pid = 0;
    char* child_argv[] = {"/bin/child", (char*)test_name, NULL};
    int wstatus;

    r = fork();
    if (r < 0)
    {
        printf("r=%d\n", r);
        assert("failed to fork child" == NULL);
    }
    else if (r == 0)
    {
        pthread_t thread;
        int r;

        printf("=== start test (%s)\n", __FUNCTION__);

        if ((r = pthread_create(&thread, NULL, _test6_thread_assert, NULL)))
        {
            printf("pthread_create() failed: %d", r);
            abort();
        }

        if (pthread_join(thread, NULL) != 0)
        {
            printf("pthread_join() failed");
            abort();
        }
    }
    else
    {
        int wstate = 0;
        r = waitpid(r, &wstate, 0);
        assert(r > 0);
        assert(WTERMSIG(wstate));
        assert(WTERMSIG(wstate) == SIGSEGV);
    }
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
    else if (
        strcmp("parent-wait-child-fork-exit-no-sighup-handler", argv[1]) == 0)
        test3(argv[1]);
    else if (
        strcmp("parent-wait-child-fork-exit-with-sighup-handler", argv[1]) == 0)
        test4(argv[1]);
    else if (strcmp("child-process-child-thread-assert", argv[1]) == 0)
        test5(argv[1]);
    else if (strcmp("child-process-child-thread-crash", argv[1]) == 0)
        test6(argv[1]);
    else
        assert("invalid option" == NULL);

    printf("goodbye from %s %s\n", argv[0], argv[1]);
}