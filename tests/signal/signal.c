// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static sem_t sem1, sem2, sem3;

/* Used by test_nested_altstack */
static sigset_t _mask_before_signal;
static sigset_t _mask_after_signal;
static uint64_t _altstack_start;
static uint64_t _altstack_end;
static int _nesting_level;
static int _sigsegv_done;
uint64_t _rsp[2];

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

int sig_block_signum = 0;
int sig_block_handler_signum = 0;

void sig_block_handler(int signum)
{
    sig_block_handler_signum = signum;
}

static void* sleep_thread_func_signal_blocked(void* in)
{
    long seconds = (long)in;
    thread_finished = 0;

    sig_block_handler_signum = 0;
    sighandler_t prevhandler = signal(sig_block_signum, sig_block_handler);

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

    assert(sig_block_handler_signum == 0);

    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    assert(sig_block_handler_signum == sig_block_signum);

    return NULL;
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

    sig_block_signum = signum;

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

static void* param_addr = NULL;

bool _in_range(void* ptr, void* base, size_t len)
{
    return ptr >= base && ptr < base + len;
}

void _altstack_handler(int signum, siginfo_t* siginfo, void* context)
{
    ucontext_t* ucontext = (ucontext_t*)context;
    param_addr = &signum;
    ucontext->uc_mcontext.gregs[REG_RIP] += 6; // non-portable.
}

int test_altstack(const char* test_name)
{
    stack_t ss, ss_old;
    struct sigaction sa = {0};

    ss.ss_sp = malloc(SIGSTKSZ);
    assert(ss.ss_sp);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;

    assert(sigaltstack(&ss, &ss_old) == 0);
    assert(ss_old.ss_flags & SS_DISABLE);

    sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
    sa.sa_sigaction = _altstack_handler;
    assert(sigaction(SIGSEGV, &sa, NULL) == 0);

    *(int*)0 = 0; // trigger SIGSEGV

    // Make sure the handler was called on the alt stack
    assert(_in_range(param_addr, ss.ss_sp, ss.ss_size));

    ss.ss_flags = SS_DISABLE;
    assert(sigaltstack(&ss, NULL) == 0);

    *(int*)0 = 0; // trigger SIGSEGV

    // Make sure the handler was not called on the alt stack
    assert(!_in_range(param_addr, ss.ss_sp, ss.ss_size));

    signal(SIGSEGV, SIG_DFL); // reset the signal handler

    printf("=== : Test passed (%s)\n", test_name);
}

void test_sig_zero()
{
    // check process existence via signal 0
    int ret = kill(getpid(), 0);
    assert(ret == 0);

    // check for non-existent process
    ret = kill(1000, 0);
    assert(ret == -1 && errno == ESRCH);

    printf("=== : Test passed (%s)\n", __FUNCTION__);
}

static uint64_t _sigset_to_uint64(const sigset_t* set)
{
    uint64_t* p = (uint64_t*)set;
    return *p;
}

static void _nested_sigsegv_handler(
    int signum,
    siginfo_t* siginfo,
    void* context)
{
    ucontext_t* ucontext = (ucontext_t*)context;
    sigset_t mask;
    int result;

    assert(_nesting_level < 2);

    asm volatile("mov %%rsp, %0" : "=r"(_rsp[_nesting_level]));

    printf(
        "sigsegv handler rsp=0x%lx, nesting level=%d, altstack=[0x%lx, "
        "0x%lx]\n",
        _rsp[_nesting_level],
        _nesting_level,
        _altstack_start,
        _altstack_end);

    assert(
        _rsp[_nesting_level] > _altstack_start &&
        _rsp[_nesting_level] < _altstack_end);

    /* test get altstack info */
    stack_t oldss;
    assert(sigaltstack(NULL, &oldss) == 0);

    /* the SS_ONSTACK is expected to be set */
    assert(oldss.ss_flags & SS_ONSTACK);

    /* negative test of setting altstack */
    {
        stack_t ss;
        ss.ss_size = SIGSTKSZ * 4; // 8 pages
        ss.ss_flags = 0;
        assert((ss.ss_sp = malloc(SIGSTKSZ * 4)) != NULL);

        /* Expect sigaltstack to fail if it is currently used */
        assert(sigaltstack(&ss, NULL) == -1);
        free(ss.ss_sp);
    }

    assert(sigprocmask(0, NULL, &mask) == 0);

    /* expect mask not equal to _mask_before_signal (i.e., the sa_mask from
     * sigaction should temporarily apply to signal mask) */
    assert(_sigset_to_uint64(&mask) != _sigset_to_uint64(&_mask_before_signal));

    ucontext->uc_mcontext.gregs[REG_RIP] += 6; // non-portable.

    _nesting_level++;

    /* test single nesting exception */
    if (_nesting_level < 2)
    {
        *(int*)0 = 0; // trigger SIGSEGV
    }

    if (siginfo->si_signo == SIGSEGV)
        _sigsegv_done = 1;
}

static void test_nested_altstack()
{
    // setup alt stack
    stack_t ss;
    ss.ss_size = SIGSTKSZ * 4; // 8 pages
    ss.ss_flags = 0;
    assert((ss.ss_sp = malloc(SIGSTKSZ * 4)) != NULL);
    assert(sigaltstack(&ss, NULL) != -1);

    _altstack_start = (uint64_t)ss.ss_sp;
    _altstack_end = _altstack_start + ss.ss_size;

    struct sigaction act = {0};
    act.sa_sigaction = _nested_sigsegv_handler;
    act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;

    assert(sigemptyset(&act.sa_mask) == 0);

    assert(sigaddset(&act.sa_mask, SIGUSR2) == 0);

    if (sigaction(SIGSEGV, &act, NULL) < 0)
    {
        assert(0 && "Error - sigaction failed unexpectedly\n");
    }

    /* test get altstack info */
    stack_t oldss;
    assert(sigaltstack(NULL, &oldss) == 0);

    /* the SS_ONSTACK is expected not to be set */
    assert(!(oldss.ss_flags & SS_ONSTACK));

    assert(sigprocmask(0, NULL, &_mask_before_signal) == 0);

    *(int*)0 = 0; // trigger SIGSEGV

    assert(_sigsegv_done == 1);

    /* ensure both signal handler calls use different rsp */
    assert(_rsp[0] > _rsp[1]);

    assert(sigprocmask(0, NULL, &_mask_after_signal) == 0);

    /* expect the signal mask remain the same after signal handling */
    assert(
        _sigset_to_uint64(&_mask_before_signal) ==
        _sigset_to_uint64(&_mask_after_signal));

    printf("=== : Test passed (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    const char* target = getenv("MYST_TARGET");

    test_pthread_cancel("pthread_cancel");

    test_signal_blocked(SIGTERM, "signal_blocked");

    test_signal_blocked(SIGABRT, "signal_blocked");

    test_raise(35, "raise");

    test_altstack("signal alt stack");

    test_sig_zero();

    /* The nested altstack is not supported by the Linux target */
    if (target && strcmp(target, "linux") != 0)
        test_nested_altstack();

    printf("\n=== passed test (%s)\n", argv[0]);

    return 0;
}
