// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

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

int main(int argc, const char* argv[])
{
    pthread_t sthread;
    pthread_t cthread;

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
