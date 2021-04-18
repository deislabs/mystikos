// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <myst/tee.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

const uint16_t port = 12345;
const size_t num_clients = 1;

void run_server(uint16_t port, size_t num_clients);

static void _sleep_msec(uint32_t msec)
{
    struct timespec ts;
    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

static void* _server_thread_func(void* arg)
{
    run_server(port, num_clients);
}

void run_client(uint16_t port);

static void* _client_thread_func(void* arg)
{
    run_client(port);
}

static void* _poll_forever_thread(void* arg)
{
    /* wait forever */
    int r = poll(NULL, 0, -1);
    assert(r == 0);

    return arg;
}

int main(int argc, const char* argv[])
{
    pthread_t sthread;
    pthread_t cthread;

    /* Test SYS_myst_poll_wake system call */
    {
        pthread_t thread;

        /* create a thread that will poll forever */
        assert(pthread_create(&thread, NULL, _poll_forever_thread, NULL) == 0);

        /* use extended syscall to break out of poll() */
        syscall(SYS_myst_poll_wake);

        pthread_join(thread, NULL);
    }

    /* Test poll() with illegal parameters */
    assert(poll(NULL, 1, 0) == -1);
    assert(errno == EFAULT);

    /* Test that first parameter is ignored when nfds == 0 */
    assert(poll((void*)1, 0, 0) == 0);

    assert(pthread_create(&sthread, NULL, _server_thread_func, NULL) == 0);
    _sleep_msec(100);
    assert(pthread_create(&cthread, NULL, _client_thread_func, NULL) == 0);

    pthread_join(cthread, NULL);
    pthread_join(sthread, NULL);

    /* Test poll() with nfds == 0 */
    {
        struct timeval tv0 = {0L, 0L};
        assert(gettimeofday(&tv0, NULL) == 0);
        const uint64_t t0 = tv0.tv_sec * 1000000 + tv0.tv_usec;

        assert(poll(NULL, 0, 500) == 0);

        struct timeval tv1 = {0L, 0L};
        assert(gettimeofday(&tv1, NULL) == 0);
        const uint64_t t1 = tv1.tv_sec * 1000000 + tv1.tv_usec;
        const uint64_t delta = t1 - t0;

        assert(t1 > t0);
        assert(delta >= 490000 && delta <= 510000);
    }

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
