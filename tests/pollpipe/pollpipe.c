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
#include <unistd.h>

#define ITERATIONS 1000

#define TRACE
#ifdef TRACE
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
static int _failed = 0;

static void _sleep_msec(uint32_t msec)
{
    struct timespec ts;
    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

static void* _reader(void* arg)
{
    int* pipefd = (int*)arg;
    (void)pipefd;

    for (size_t i = 0; i < ITERATIONS; i++)
    {
        struct pollfd fds;
        int n;
        char buf[sizeof(alphabet)];

        fds.fd = pipefd[0];
        fds.events = POLLIN;

        while ((n = poll(&fds, 1, 1000)) == -1 && errno == EINTR)
        {
            T(printf("retry poll()\n"));
        }

        T(printf("poll returned %d\n", n));
        if (n != 1)
        {
            assert(n == 1);
            _failed = 1;
            return NULL;
        }

        T(printf("read:  %zu\n", i);)
        ssize_t count = read(pipefd[0], buf, sizeof(buf));

        if (count != sizeof(alphabet))
            printf("count=%zu\n", count);
        assert(count == sizeof(alphabet));
        assert(strcmp(buf, alphabet) == 0);
    }

    return NULL;
}

static void* _writer(void* arg)
{
    int* pipefd = (int*)arg;
    (void)pipefd;

    for (size_t i = 0; i < ITERATIONS; i++)
    {
        T(printf("write: %zu\n", i);)
        ssize_t n = write(pipefd[1], alphabet, sizeof(alphabet));

        if (n != sizeof(alphabet))
            printf("n=%zu\n", n);

        assert(n == sizeof(alphabet));
    }

    return NULL;
}

int main(int argc, const char* argv[])
{
    int pipefd[2];
    pthread_t reader;
    pthread_t writer;

    assert(pipe(pipefd) == 0);

    assert(pthread_create(&reader, NULL, _reader, pipefd) == 0);
    _sleep_msec(100);
    assert(pthread_create(&writer, NULL, _writer, pipefd) == 0);

    assert(pthread_join(writer, NULL) == 0);
    assert(pthread_join(reader, NULL) == 0);

    assert(close(pipefd[0]) == 0);
    assert(close(pipefd[1]) == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return _failed ? -1 : 0;
}
