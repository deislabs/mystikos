// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <myst/assume.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SEGFAULT 139
#define SIGSEGV 11

extern int myst_fork(void);

int _printf(const char* fmt, ...)
{
    static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
    va_list ap;

    va_start(ap, fmt);
    pthread_mutex_lock(&_lock);
    fprintf(stderr, "tid=%ld: ", syscall(SYS_gettid));
    vfprintf(stderr, fmt, ap);
    fflush(stderr);
    pthread_mutex_unlock(&_lock);
    va_end(ap);
}

int _test(int argc, const char* argv[], bool enosys)
{
    int ret = -1;
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        _printf("*** inside child\n");
        int ret = reboot(0);
        if (enosys && ret != ENOSYS)
        {
            _printf("Expecting ENOSYS to be returned\n");
            exit(EXIT_FAILURE);
        }
        else if (enosys)
        {
            _printf("ENOSYS returned as expected\n");
        }
        _printf("Shutting down child\n");
        exit(EXIT_SUCCESS);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Waiting for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(
                stderr,
                "waitpid on child pid did not return child pid.\n Return val = "
                "%d\n",
                pid);
            exit(EXIT_FAILURE);
        }
        if (enosys)
        {
            // when ENOSYS is returned
            if (WIFSIGNALED(wstatus) || !WIFEXITED(wstatus))
            {
                fprintf(stderr, "waitpid WIFEXITED should be set.\n");
                exit(EXIT_FAILURE);
            }
            if ((WEXITSTATUS(wstatus) != EXIT_SUCCESS))
            {
                fprintf(
                    stderr,
                    "waitpid WEXITSTATUS should be 0 as child did exit(0). "
                    "Exit status=%d\n",
                    wstatus);
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            // when myst_panic is called
            if (!WIFSIGNALED(wstatus) || WIFEXITED(wstatus))
            {
                fprintf(stderr, "waitpid WIFSIGNALED should be set.\n");
                exit(EXIT_FAILURE);
            }
            if ((WTERMSIG(wstatus) != SIGSEGV))
            {
                fprintf(
                    stderr,
                    "waitpid WTERMSIG should be SIGSEGV as child did exit(1). "
                    "wtermsig=%d\n",
                    WTERMSIG(wstatus));
                exit(EXIT_FAILURE);
            }
        }
        _printf("Shutting down parent\n");
    }
    return EXIT_SUCCESS;
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Not enough args... which test?\n");
        return -1;
    }
    if (strcmp(argv[1], "false") == 0)
    {
        myst_assume(_test(argc, argv, false) == 0);
    }
    else if (strcmp(argv[1], "true") == 0)
    {
        myst_assume(_test(argc, argv, true) == 0);
    }
    else
    {
        fprintf(stderr, "invalid argument\n");
        return -1;
    }
    return 0;
}
