// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static sem_t sem1, sem2, sem3;

static void* start_async(void* arg)
{
    (void)arg;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
    sem_post(&sem1);
    for (;;)
    {
        // We have to trigger a syscall to reach a cancellation point.
        sleep(1);
    }
    return 0;
}

static void cleanup1(void* arg)
{
    *(int*)arg = 1;
}

static void cleanup2(void* arg)
{
    *(int*)arg += 2;
}

static void cleanup3(void* arg)
{
    *(int*)arg += 3;
}

static void cleanup4(void* arg)
{
    *(int*)arg += 4;
}

static void* start_single(void* arg)
{
    pthread_cleanup_push(cleanup1, arg);
    sem_post(&sem2);
    sleep(3);
    pthread_cleanup_pop(0);
    return 0;
}

static void* start_nested(void* arg)
{
    int* foo = arg;
    pthread_cleanup_push(cleanup1, foo);
    pthread_cleanup_push(cleanup2, foo + 1);
    pthread_cleanup_push(cleanup3, foo + 2);
    pthread_cleanup_push(cleanup4, foo + 3);
    sem_post(&sem3);
    sleep(3);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return 0;
}

static int test_pthread_cancel(const char* test_name)
{
    pthread_t td;
    int r;
    void* res;
    _Atomic(int) foo[4];

    assert(sem_init(&sem1, 0, 0) == 0 && "creating semaphore");
    assert(sem_init(&sem2, 0, 0) == 0 && "creating semaphore");
    assert(sem_init(&sem3, 0, 0) == 0 && "creating semaphore");

    /* Asynchronous cancellation */
    assert(
        pthread_create(&td, 0, start_async, &sem1) == 0 &&
        "failed to create thread");
    while (sem_wait(&sem1))
        ;
    assert(pthread_cancel(td) == 0 && "failed to cancel");
    assert(pthread_join(td, &res) == 0 && "failed to join");
    assert(res == PTHREAD_CANCELED && "canceled thread exit status");

    printf("=== : Test 1 passed (%s)\n", test_name);

    // /* Cancellation cleanup handlers */
    foo[0] = 0;
    assert(
        pthread_create(&td, 0, start_single, foo) == 0 &&
        "failed to create thread");

    while (sem_wait(&sem2))
        ;
    assert(pthread_cancel(td) == 0 && "failed to cancel");
    assert(pthread_join(td, &res) == 0 && "failed to join");
    assert(res == PTHREAD_CANCELED && "canceled thread exit status");
    assert(foo[0] == 1 && "cleanup handler failed to run");

    printf("=== : Test 2 passed (%s)\n", test_name);

    /* Nested cleanup handlers */
    memset(foo, 0, sizeof foo);
    assert(
        pthread_create(&td, 0, start_nested, foo) == 0 &&
        "failed to create thread");
    while (sem_wait(&sem3))
        ;
    assert(pthread_cancel(td) == 0 && "failed to cancel");
    assert(pthread_join(td, &res) == 0 && "failed to join");
    assert(res == PTHREAD_CANCELED && "canceled thread exit status");
    assert(foo[0] == 1 && "cleanup handler failed to run");
    assert(foo[1] == 2 && "cleanup handler failed to run");
    assert(foo[2] == 3 && "cleanup handler failed to run");
    assert(foo[3] == 4 && "cleanup handler failed to run");

    printf("=== : Test 3 passed (%s)\n", test_name);
    return 0;
}

static _Atomic int thread_finished = 0;

static int child_tid = 0;

static void* sleep_thread_func(void* in)
{
    long seconds = (long)in;
    thread_finished = 0;

    child_tid = syscall(SYS_gettid);
    for (int i = 0; i < seconds; i++)
    {
        sleep(1); // sleep 1s
        sched_yield();
    }
    thread_finished = 1;
    return NULL;
}

static void* sleep_thread_func_signal_blocked(void* in)
{
    long seconds = (long)in;
    thread_finished = 0;

    sigset_t mask, mask_old;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &mask_old);

    child_tid = syscall(SYS_gettid);
    for (int i = 0; i < seconds; i++)
    {
        sleep(1); // sleep 1s
        sched_yield();
    }
    thread_finished = 1;

    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    return NULL;
}

int test_signal_nonblocked(int signum, const char* test_name)
{
    pthread_t thread;
    void* retval;
    child_tid = 0;

    assert(pthread_create(&thread, 0, sleep_thread_func, (void*)3) == 0);

    while (child_tid == 0)
        ;
    pthread_kill(thread, signum);
    printf("Send signal %d to child thread %d\n", signum, child_tid);

    sleep(4);
    assert(thread_finished == 0);

    printf("=== : Test passed (%s)\n", test_name);
}

int is_blockable_signal(int signum)
{
    return signum != SIGKILL && signum != SIGSTOP;
}

int test_signal_blocked(int signum, const char* test_name)
{
    pthread_t thread;
    void* retval;
    child_tid = 0;

    assert(
        pthread_create(
            &thread, 0, sleep_thread_func_signal_blocked, (void*)3) == 0);

    while (child_tid == 0)
        ;

    // Try using syscall, instead of pthread_kill, to deliver the signal.
    syscall(SYS_tkill, child_tid, signum);
    printf("Send signal %d to child thread %d\n", signum, child_tid);

    sleep(4);

    // Since the signal is blocked, the child thread must have reached its end,
    // unless this is a signal can't be blocked, such as SIGKILL.
    assert(
        is_blockable_signal(signum) && thread_finished != 0 ||
        !is_blockable_signal(signum) && thread_finished == 0);

    printf("=== : Test passed (%s)\n", test_name);
}

static _Atomic(int) _dummy_cnt = 0;
void dummy_handler(int signum)
{
    _dummy_cnt = 1;
}

int test_raise(int signum, const char* test_name)
{
    _dummy_cnt = 0;
    signal(signum, dummy_handler);
    raise(signum);
    sleep(1);
    assert(_dummy_cnt == 1);
    printf("=== : Test passed (%s)\n", test_name);
}

int main(int argc, const char* argv[])
{
    test_pthread_cancel("pthread_cancel");

    test_signal_nonblocked(SIGTERM, "signal_nonblocked");

    test_signal_blocked(SIGTERM, "signal_blocked");

    test_signal_blocked(SIGKILL, "signal_blocked");

    test_raise(35, "raise");

    printf("\n=== passed test (%s)\n", argv[0]);

    return 0;
}
