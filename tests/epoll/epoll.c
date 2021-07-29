// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

const uint16_t port = 12345;
const size_t num_clients = 2;

static void _sleep_msec(uint32_t msec)
{
    struct timespec ts;
    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

static void* _server_thread_func(void* arg)
{
    extern void run_server(uint16_t port, size_t num_clients);
    run_server(port, num_clients);
}

static void* _client_thread_func(void* arg)
{
    extern void run_client(uint16_t port);
    run_client(port);
}

static void test_epoll_on_regular_files_unsupp()
{
    /* epoll on regular files should fail with an EPERM */
    int fd = creat("/tmp/file", 0666);
    assert(fd >= 0);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    assert(epfd != -1);
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    assert(ret == -1 && errno == EPERM);

    ret = unlink("/tmp/file");
    assert(ret == 0);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

static void test_epoll_fcntl()
{
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    assert(epfd != -1);
    // check fcntl returns appropriate flag
    assert(fcntl(epfd, F_GETFD) & FD_CLOEXEC);
    // clear cloexec flag
    fcntl(epfd, F_SETFD, 0);
    assert(!(fcntl(epfd, F_GETFD) & FD_CLOEXEC));
    // reset cloexec flag
    fcntl(epfd, F_SETFD, FD_CLOEXEC);
    assert(fcntl(epfd, F_GETFD) & FD_CLOEXEC);
    close(epfd);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    test_epoll_on_regular_files_unsupp();
    test_epoll_fcntl();

    pthread_t sthread;
    pthread_t cthread1;
    pthread_t cthread2;

    assert(pthread_create(&sthread, NULL, _server_thread_func, NULL) == 0);
    _sleep_msec(250);
    assert(pthread_create(&cthread1, NULL, _client_thread_func, NULL) == 0);
    assert(pthread_create(&cthread2, NULL, _client_thread_func, NULL) == 0);

    pthread_join(cthread1, NULL);
    pthread_join(cthread2, NULL);
    pthread_join(sthread, NULL);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
