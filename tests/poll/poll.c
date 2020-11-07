// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>

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

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
