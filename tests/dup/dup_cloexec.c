// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int test_dup_cloexec()
{
    int fd1, fd2;
    FILE* out;

    if (!(out = fopen("/tmp/file", "w")))
    {
        printf("fopen error: %i\n", errno);
        assert(false);
    }

    fd1 = fileno(out);
    assert(fd1 > 0);

    assert(fcntl(fd1, F_SETFD, FD_CLOEXEC) == 0);

    int fdflags = fcntl(fd1, F_GETFD);
    assert(fdflags == FD_CLOEXEC);

    fd2 = dup(fd1);

    // FD_CLOEXEC is not inherited on dup
    fdflags = fcntl(fd2, F_GETFD);
    assert(fdflags == 0);

    char fd1_char[5];
    char fd2_char[5];
    sprintf(fd1_char, "%d", fd1);
    sprintf(fd2_char, "%d", fd2);

    printf("Calling exec\n");
    char* args[] = {"./exec_prog", fd1_char, fd2_char, NULL};
    int execret = execvp(args[0], args);
    printf("errono %i", errno);

    printf("Test failed execvp returned %i\n", execret);
    close(fd1);
    close(fd2);
    assert(execret == 0);
}

int main(int argc, const char* argv[])
{
    printf("test_dup_cloexec exec\n");
    test_dup_cloexec();

    return 0;
}
