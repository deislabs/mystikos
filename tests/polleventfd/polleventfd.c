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
#include <sys/eventfd.h>
#include <unistd.h>

#define ITERATIONS 1000

#ifdef TRACE
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

static int efd;

static void _sleep_msec(uint32_t msec)
{
    struct timespec ts;
    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

static void* _reader(void* arg)
{
    for (size_t i = 0; i < ITERATIONS; i++)
    {
        struct pollfd fds;
        int n;

        fds.fd = efd;
        fds.events = POLLIN;

        while ((n = poll(&fds, 1, 1000)) == -1 && errno == EINTR)
        {
            T(printf("retry poll()\n"));
        }

        assert(n == 1);

        uint64_t val;
        ssize_t count = read(efd, &val, sizeof(val));
        T(printf("read: %zu %zu %lu\n", i, count, val);)
        assert(count == sizeof(val));
    }

    return NULL;
}

static void* _writer(void* arg)
{
    int* pipefd = (int*)arg;
    (void)pipefd;

    for (uint64_t i = 0; i < ITERATIONS; i++)
    {
        T(printf("write: i=%zu\n", i););
        uint64_t val = 1;
        ssize_t n = write(efd, &val, sizeof(val));
        assert(n == sizeof(val));
    }

    return NULL;
}

int main(int argc, const char* argv[])
{
    pthread_t reader;
    pthread_t writer;

    efd = eventfd(0, EFD_SEMAPHORE);

    assert(pthread_create(&reader, NULL, _reader, NULL) == 0);
    _sleep_msec(100);
    assert(pthread_create(&writer, NULL, _writer, NULL) == 0);

    assert(pthread_join(writer, NULL) == 0);
    assert(pthread_join(reader, NULL) == 0);

    assert(close(efd) == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
