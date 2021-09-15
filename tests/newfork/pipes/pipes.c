// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    int pipefd[2];
    pid_t pid;
    const char msg[] = "abcdefghijklmnopqrstuvwxyz";
    size_t iterations = 10;

    assert(pipe(pipefd) == 0);

    if ((pid = fork()) < 0) /* error */
    {
        fprintf(stderr, "%s: fork failed\n", argv[0]);
        exit(1);
    }
    else if (pid > 0) /* parent */
    {
        printf("=== parent(pid=%d)\n", pid);

        /* close write end of the pipe */
        assert(close(pipefd[1]) == 0);

        /* read messages from the child */
        for (size_t i = 0; i < iterations; i++)
        {
            char buf[sizeof(msg)];
            assert(read(pipefd[0], buf, sizeof(buf)) == sizeof(msg));
            assert(strcmp(buf, msg) == 0);
            printf("=== parent read {%s}\n", buf);
        }

        assert(close(pipefd[0]) == 0);

        /* wait for child to exit */
        int wstatus;
        printf("=== parent waiting on child\n");
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        assert(WEXITSTATUS(wstatus) == 123);

        printf("=== passed all tests (%s)\n", argv[0]);
        exit(0);
    }
    else /* child */
    {
        printf("=== child(pid=%d)\n", pid);

        /* close read end of the pipe */
        assert(close(pipefd[0]) == 0);

        /* write messages to the parent */
        for (size_t i = 0; i < iterations; i++)
        {
            ssize_t n = write(pipefd[1], msg, sizeof(msg));
            assert(n == sizeof(msg));
        }

        assert(close(pipefd[1]) == 0);

        printf("=== child exit\n");
        _exit(123);
    }

    return 0;
}
