// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../utils/utils.h"
#include "common.h"

const uint16_t port = 12480;
const size_t num_clients = 1;

static void* _server_thread_func(void* arg)
{
    run_server(port);
}

static void* _client_thread_func(void* arg)
{
    run_client(port);
}

int main(int argc, const char* argv[])
{
    pthread_t sthread;
    pthread_t cthread;

    assert(pthread_create(&sthread, NULL, _server_thread_func, NULL) == 0);
    sleep_msec(100);
    assert(pthread_create(&cthread, NULL, _client_thread_func, NULL) == 0);

    pthread_join(cthread, NULL);
    pthread_join(sthread, NULL);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
