// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void test_set_nonblock()
{
    int pipefd[2];
    int ret = 0;
    int flags = 0;

    ret = pipe(pipefd);
    assert(ret == 0);

    flags = fcntl(pipefd[0], F_GETFL, 0);
    assert(flags >= 0);

    ret = fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    assert(ret == 0);

    flags = fcntl(pipefd[0], F_GETFL, 0);
    assert(flags >= 0 && (flags & O_NONBLOCK));
}

void test_set_append()
{
    int ret = 0;
    int flags = 0;
    char* fname = "tmp.txt";
    int fd = open(fname, O_RDWR | O_CREAT);

    flags = fcntl(fd, F_GETFL, 0);
    assert(flags >= 0 && !(flags & O_APPEND));

    ret = fcntl(fd, F_SETFL, flags | O_APPEND);
    assert(ret == 0);

    flags = fcntl(fd, F_GETFL, 0);
    assert(flags >= 0 && (flags & O_APPEND));

    close(fd);
    unlink(fname);
}

int main(int argc, const char* argv[])
{
    test_set_nonblock();

    test_set_append();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
