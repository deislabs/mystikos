// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CHECK(ret) \
    if (ret != 0)  \
        exit(-1);

#define TEST1_EXIT_STATUS 0
#define TEST2_EXIT_STATUS 2

void* thread_exit(void* _args)
{
    int* args = (int*)_args;
    int code = *args;
    fprintf(stderr, "calling exit(%d) from thread_exit\n", code);
    exit(code);
}

int test1_child()
{
    pthread_t child;
    int code = TEST1_EXIT_STATUS;
    pthread_create(&child, NULL, thread_exit, &code);
    pthread_join(child, NULL);
    return -1;
}

int test1()
{
    pid_t pid = 0;
    int wstatus = 0;
    char* const argv[] = {"/bin/exit_status", "test1-child", NULL};

    if (posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL) != 0)
        return -1;

    if (waitpid(pid, &wstatus, 0) != pid)
        return -1;
    if (!WIFEXITED(wstatus) || (WEXITSTATUS(wstatus) != TEST1_EXIT_STATUS))
    {
        fprintf(stderr, "didnt return the correct exit status\n");

        return -1;
    }

    return 0;
}

int test2_child()
{
    pthread_t child;
    int code = TEST2_EXIT_STATUS;
    pthread_create(&child, NULL, thread_exit, &code);
    pthread_join(child, NULL);
    return -1;
}

int test2()
{
    pid_t pid = 0;
    int wstatus = 0;
    char* const argv[] = {"/bin/exit_status", "test2-child", NULL};

    if (posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL) != 0)
        return -1;

    if (waitpid(pid, &wstatus, 0) != pid)
        return -1;
    if (WEXITSTATUS(wstatus) != TEST2_EXIT_STATUS)
    {
        fprintf(stderr, "didnt return the correct exit status\n");
        return -1;
    }

    return 0;
}

int tests()
{
    CHECK(test1());
    CHECK(test2());

    return 0;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
        exit(-1);

    if (strcmp(argv[1], "tests") == 0)
        return tests();
    else if (strcmp(argv[1], "test1-child") == 0)
        return test1_child();
    else if (strcmp(argv[1], "test2-child") == 0)
        return test2_child();
    else
        return -1;
}
