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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
static sigset_t sigmask, sigmask_int;
static struct timespec timeout_ts;
void setup()
{
    memset(&sigmask, 0, sizeof(sigmask));
    memset(&sigmask_int, 0, sizeof(sigmask_int));
    assert(sigaddset(&sigmask_int, SIGINT) == 0);
    memset(&timeout_ts, 0, sizeof(timeout_ts));
    timeout_ts.tv_sec = 5;
    timeout_ts.tv_nsec = 0; // 50 ms
    sigprocmask(SIG_BLOCK, &sigmask_int, NULL);
}
#if 0
// Test ppoll on illegal args
void test_ppoll_illegal_args()
{
    int fd0 = open("/dev/null", O_RDONLY);
    int fd1 = open("/dev/urandom", O_RDONLY);
    struct pollfd fds[2];
    fds[0].fd = fd0;
    fds[0].events = POLLIN | POLLOUT | POLLPRI;
    fds[1].fd = fd1;
    fds[1].events = POLLIN;
    /* Test ppoll() with illegal parameters (fds) */
    assert(ppoll(NULL, 2, &timeout_ts, &sigmask) == -1);
    assert(errno == EFAULT);
    /* Test that first parameter is ignored when nfds == 0 */
    assert(ppoll((void*)1, 0, &timeout_ts, &sigmask) == 0);
    close(fd0);
    close(fd1);
}
#endif
void send_sigint(void* pid)
{
    for (int i = 0; i < 3; i++)
    {
        sleep(1);
        printf("sending sigint to pid, %i\n", (long)pid);
        kill((long)pid, SIGINT);
        printf("sent sigint to pid, %i\n", (long)pid);
    }
}
#if 0
// no mask
void test_ppoll_success()
{
    int fd0 = open("/dev/null", O_RDONLY);
    printf("fd0 is %i !!!!\n", fd0);
    struct pollfd fds[1];
    fds[0].fd = fd0;
    fds[0].events = POLLIN | POLLOUT;
    assert(ppoll(fds, 1, &timeout_ts, &sigmask) == 1);
}
int test_ppoll_success_signal_mask()
{
    int fd0 = open("/dev/null", O_RDONLY);
    struct pollfd fds[1];
    fds[0].fd = fd0;
    fds[0].events = POLLIN | POLLOUT;
    pthread_t threadId;
    assert(pthread_create(&threadId, NULL, &send_sigint, (void *)getpid()) == 0);
    assert(ppoll(fds, 1, &timeout_ts, &sigmask_int) == 1);
    assert(pthread_join(threadId, NULL) == 0);
}
#endif
int test_ppoll_success_signal_mask2()
{
    pthread_t threadId;
    assert(pthread_create(&threadId, NULL, &send_sigint, (void*)getpid()) == 0);
    printf("errno is %i\n", errno);
    printf(
        "ppoll returns %d\n",
        ppoll(NULL, 0, &timeout_ts, &sigmask_int)); // fails with EINTR
    printf("errno is %i\n", errno);
    assert(pthread_join(threadId, NULL) == 0);
}
#if 0
int test_ppoll_failure_signal_nomask()
{
    pthread_t threadId;
    assert(pthread_create(&threadId, NULL, &send_sigint, (void *)getpid()) == 0);
    assert(ppoll(NULL, 0, &timeout_ts, &sigmask) == -1);
    assert(errno == 4);
    assert(pthread_join(threadId, NULL) == 0);
}
#endif
int main(int argc, const char* argv[])
{
    setup();
    // test_ppoll_illegal_args();
    // printf("1!\n");
    // test_ppoll_success();
    // printf("2!\n");
    // test_ppoll_success_signal_mask();
    // printf("3!\n");
    test_ppoll_success_signal_mask2(); // fails
    // printf("4!\n");
    // test_ppoll_failure_signal_nomask();
    // printf("5!\n");
    // printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
