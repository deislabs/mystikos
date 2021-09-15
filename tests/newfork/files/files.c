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
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    pid_t pid;
    uint64_t magic = 0x182c8e7106d5445e;

    if ((pid = fork()) < 0) /* error */
    {
        fprintf(stderr, "%s: fork failed\n", argv[0]);
        exit(1);
    }
    else if (pid > 0) /* parent */
    {
        /* wait for child to exit */
        int wstatus;
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        assert(WEXITSTATUS(wstatus) == 123);

        /* read file */
        uint64_t x;
        int fd = open("/tmp/shared", O_RDONLY);
        assert(fd >= 0);
        ssize_t n = read(fd, &x, sizeof(x));
        assert(n == sizeof(x));
        assert(x == magic);

        printf("=== passed all tests (%s)\n", argv[0]);
        exit(0);
    }
    else /* child */
    {
        int fd = open("/tmp/shared", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        assert(fd >= 0);
        assert(write(fd, &magic, sizeof(magic)) == sizeof(magic));
        _exit(123);
    }

    return 0;
}
