// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern int myst_fork(void);

int _gettid(void)
{
    return syscall(SYS_gettid);
}

int _printf(const char* fmt, ...)
{
    static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
    va_list ap;

    va_start(ap, fmt);
    pthread_mutex_lock(&_lock);
    fprintf(stderr, "_printf: tid=%d: ", _gettid());
    vfprintf(stderr, fmt, ap);
    fflush(stderr);
    pthread_mutex_unlock(&_lock);
    va_end(ap);
}

void point()
{
}

int test_fork1(int argc, const char* argv[])
{
    pid_t pid = fork();
    // pid_t pid = syscall(SYS_fork);

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child\n");
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Waiting for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 1)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_fork2(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. sleeping\n");
        sleep(1);
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Waiting for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 1)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        if (WIFSIGNALED(wstatus) != 0)
        {
            fprintf(stderr, "waitpid WIFSIGNALED was not sent a kill.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_fork3(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. sleeping and waiting for signal\n");
        sleep(1);
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Sending signal to shut down child\n");
        kill(pid, SIGKILL);
        _printf("Waiting for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFSIGNALED(wstatus))
        {
            fprintf(stderr, "waitpid WIFSIGNALED should be set.\n");
            exit(1);
        }
        if (WTERMSIG(wstatus) != 9)
        {
            fprintf(
                stderr,
                "waitpid WTERMSIG should be 9 as child was killed via "
                "SIGKILL).\n");
            exit(1);
        }
        if (WIFSIGNALED(wstatus) == 0)
        {
            fprintf(
                stderr,
                "waitpid WIFSIGNALED should have told us child was killed.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_fork4(int argc, const char* argv[])
{
    pid_t pid = fork();
    int variable = 0;

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. setting variable\n");
        variable = 1;
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("waiting for child to shut down\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 1)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        if (variable != 0)
        {
            fprintf(stderr, "Variable should not be changed.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_fork5(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. setting variable\n");
        const char* path = "/bin/fork_child";
        if (execl(path, path, NULL) != 0)
        {
            fprintf(stderr, "%s: execl() failed: %d\n", path, pid);
            exit(2);
        }
        _printf("Shutting down child\n");
        exit(2);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("waiting for child to shut down\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 10)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_nofork1(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        if (errno == ENOTSUP)
        {
            _printf("Fork not supported as expected\n");
        }
        else
        {
            _printf(
                "%s: fork() failed with incorrect error: %d\n", argv[0], pid);
            exit(-1);
        }
    }
    else if (pid == 0)
    {
        _printf("*** inside child\n");
        _printf("fork should have fail\n");
        exit(-1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Fork should have failed\n");
        _printf("Waiting for child to shutdown\n");
        waitpid(pid, &wstatus, 0);
        exit(-1);
    }
    return 0;
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Not enough args... which test?\n");
        return -1;
    }
    if (strcmp(argv[1], "fork") == 0)
    {
        assert(test_fork1(argc, argv) == 0);
        assert(test_fork2(argc, argv) == 0);
        assert(test_fork3(argc, argv) == 0);
        assert(test_fork4(argc, argv) == 0);
        assert(test_fork5(argc, argv) == 0);
    }
    else if (strcmp(argv[1], "nofork") == 0)
    {
        assert(test_nofork1(argc, argv) == 0);
    }
    return 0;
}
