// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WRITE_SIZE 2 * PIPE_BUF * 2
#define READ_SIZE 2 * PIPE_BUF * 4

static void* _writer(void* args)
{
    int* pipefds = (int*)args;
    char buf[WRITE_SIZE];

    printf("write:\n");
    memset(buf, 0xff, sizeof(buf));
    ssize_t n = write(pipefds[1], buf, sizeof(buf));
    assert(n == sizeof(buf));
    printf("nwrite=%ld/%zu\n", n, sizeof(buf));
}

int main(int argc, const char* argv[])
{
    int pipefds[2];
    pthread_t writer;
    char buf[READ_SIZE];
    int r;

    assert(pipe(pipefds) == 0);

    r = fcntl(pipefds[0], F_SETPIPE_SZ, 12345);
    printf("set.r=%d\n", r);

    r = fcntl(pipefds[1], F_SETPIPE_SZ, 12345);
    printf("set.r=%d\n", r);

    r = fcntl(pipefds[0], F_GETPIPE_SZ);
    printf("get.r=%d\n", r);

    r = fcntl(pipefds[1], F_GETPIPE_SZ);
    printf("get.r=%d\n", r);

    assert(pthread_create(&writer, NULL, _writer, pipefds) == 0);
    printf("read:\n");
    ssize_t n = read(pipefds[0], buf, sizeof(buf));
    assert(n == WRITE_SIZE);
    printf("nread=%ld/%zu\n", n, sizeof(buf));
    pthread_join(writer, NULL);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
