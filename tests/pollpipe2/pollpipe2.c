// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

#define ITERATIONS 1

#ifdef TRACE
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

static int _gettid()
{
    return syscall(SYS_gettid);
}

static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

static int pipefd[2][2];

static void _sleep_msec(uint32_t msec)
{
    struct timespec ts;
    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

static void* _reader(void* arg)
{
    size_t thread_id = (size_t)arg;

    printf("_reader(): thread_id=%ld tid=%d\n", thread_id, _gettid());

    for (size_t i = 0; i < ITERATIONS; i++)
    {
        struct pollfd fds;
        int n;
        char buf[sizeof(alphabet)];

        fds.fd = pipefd[thread_id][0];
        fds.events = POLLIN;

        errno = 0;

        printf("Thread %ld poll on fd=%d\n", thread_id, fds.fd);

        while ((n = poll(&fds, 1, -1)) == -1 && errno == EINTR)
        {
            printf("Retry poll() on EINTR\n");
        }

        printf("Thread %ld after poll: n=%d\n", thread_id, n);

        assert(n == 1);

        printf("Thread %ld reading:  %zu\n", thread_id, i);
        ssize_t count = read(pipefd[thread_id][0], buf, sizeof(buf));
        printf("Thread %ld after reading:  %zu\n", thread_id, i);

        if (count != sizeof(alphabet))
            printf("count=%zu\n", count);
        assert(count == sizeof(alphabet));
        assert(strcmp(buf, alphabet) == 0);
    }

    return NULL;
}

static void* _writer(void* arg)
{
    size_t thread_id = (size_t)arg;

    for (size_t i = 0; i < ITERATIONS; i++)
    {
        printf(
            "write to thread %ld: %zu fd=%d\n",
            thread_id,
            i,
            pipefd[thread_id][1]);
        ssize_t n = write(pipefd[thread_id][1], alphabet, sizeof(alphabet));

        if (n != sizeof(alphabet))
            printf("n=%zu\n", n);

        assert(n == sizeof(alphabet));
    }

    return NULL;
}

int main(int argc, const char* argv[])
{
    pthread_t reader[2];
    pthread_t writer;

    assert(pipe(pipefd[0]) == 0);
    assert(pipe(pipefd[1]) == 0);

    printf("pipefd[0]=%d:%d\n", pipefd[0][0], pipefd[0][1]);

    assert(pthread_create(&reader[0], NULL, _reader, (void*)0) == 0);
    assert(pthread_create(&reader[1], NULL, _reader, (void*)1) == 0);
    _sleep_msec(1000);
    assert(pthread_create(&writer, NULL, _writer, (void*)0) == 0);

    assert(pthread_join(writer, NULL) == 0);
    printf("===  after join reader 0\n");
    assert(pthread_join(reader[0], NULL) == 0);
    printf("===  after join writer 0\n");

    printf("Closing pipe 0 only\n");
    assert(close(pipefd[0][0]) == 0);
    assert(close(pipefd[0][1]) == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
