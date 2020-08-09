// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <execinfo.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include "posix_u.h"
#include "../../../../3rdparty/libc/musl/src/posix/posix_signal.h"
#include "spinlock.h"

#define POSIX_STRUCT(PREFIX,NAME) OE_CONCAT(t_,NAME)
#include "../../../../3rdparty/libc/musl/src/posix/posix_ocall_structs.h"

OE_STATIC_ASSERT(sizeof(struct posix_timespec) == sizeof(struct t_timespec));

OE_STATIC_ASSERT(sizeof(struct posix_sigaction) == sizeof(struct t_sigaction));

OE_STATIC_ASSERT( sizeof(struct posix_siginfo) == sizeof(struct t_siginfo));

OE_STATIC_ASSERT(sizeof(struct posix_ucontext) == sizeof(struct t_ucontext));

OE_STATIC_ASSERT(sizeof(struct posix_sigset) == sizeof(struct t_sigset));

OE_STATIC_ASSERT(sizeof(struct posix_sig_args) == sizeof(struct t_sig_args));

OE_STATIC_ASSERT(sizeof(struct posix_shared_block) == sizeof(struct t_shared_block));

OE_STATIC_ASSERT(sizeof(struct t_shared_block) == OE_PAGE_SIZE);

__thread struct posix_shared_block* __posix_shared_block = NULL;

/* ATTN: single enclave instance */
static oe_enclave_t* _enclave = NULL;

int posix_gettid(void)
{
    return (int)syscall(SYS_gettid);
}

void sleep_msec(uint64_t milliseconds)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    struct timespec rem = {0, 0};
    static const uint64_t _SEC_TO_MSEC = 1000UL;
    static const uint64_t _MSEC_TO_NSEC = 1000000UL;

    ts.tv_sec = (time_t)(milliseconds / _SEC_TO_MSEC);
    ts.tv_nsec = (long)((milliseconds % _SEC_TO_MSEC) * _MSEC_TO_NSEC);

    while (nanosleep(req, &rem) != 0 && errno == EINTR)
    {
        req = &rem;
    }
}

struct posix_shared_block* __posix_init_shared_block;

void posix_print_kill(void)
{
    uint32_t val = __posix_init_shared_block->kill_lock;
    printf("posix_print_kill: val=%u\n", val);
}

void posix_lock_kill(void)
{
    if (__posix_init_shared_block)
        spin_lock(&__posix_init_shared_block->kill_lock);
}

void posix_unlock_kill(void)
{
    if (__posix_init_shared_block)
        spin_unlock(&__posix_init_shared_block->kill_lock);
}

#define TRACE

static inline void __enter(const char* func)
{
#if defined(TRACE)
    printf("__enter:%s:%d\n", func, posix_gettid());
    fflush(stdout);
#else
    (void)func;
#endif
}

static inline void __leave(const char* func)
{
#if defined(TRACE)
    printf("__leave:%s:%d\n", func, posix_gettid());
    fflush(stdout);
#else
    (void)func;
#endif
}

#define ENTER __enter(__FUNCTION__)
#define LEAVE __leave(__FUNCTION__)

void posix_print_trace(void)
{
    if (__posix_shared_block)
    {
        printf("*** posix_print_trace=%d (%d)\n", __posix_shared_block->trace,
            posix_gettid());
        fflush(stdout);
    }
    else
    {
        printf("*** posix_print_trace=null\n");
        fflush(stdout);
    }
}

extern int posix_init(oe_enclave_t* enclave)
{
    if (!enclave)
        return -1;

    _enclave = enclave;
    return 0;
}

static void* _thread_func(void* arg)
{
    int retval;
    oe_result_t r;
    uint64_t cookie = (uint64_t)arg;

    /* Allocate the page shared betweent he host and the enclave */
    if (!__posix_shared_block)
    {
        if (!(__posix_shared_block = calloc(1, sizeof(struct posix_shared_block))))
        {
            fprintf(stderr, "posix_run_thread_ecall(): calloc() failed\n");
            fflush(stderr);
            abort();
        }
    }

#if 1
    printf("CHILD.START=%d\n", posix_gettid());
    fflush(stdout);
#endif

    int tid = posix_gettid();

    if ((r = posix_run_thread_ecall(
        _enclave, &retval, cookie, tid, __posix_shared_block)) != OE_OK)
    {
        fprintf(stderr, "posix_run_thread_ecall(): result=%u\n", r);
        fflush(stderr);
        abort();
    }

    if (retval != 0)
    {
        fprintf(stderr, "posix_run_thread_ecall(): retval=%d\n", retval);
        fflush(stderr);
        abort();
    }


#if 1
    printf("CHILD.EXIT=%d\n", posix_gettid());
    fflush(stdout);
#endif

    free(__posix_shared_block);
    __posix_shared_block = NULL;

    return NULL;
}

int posix_start_thread_ocall(uint64_t cookie)
{
    ENTER;
    int ret = -1;
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&t, &attr, _thread_func, (void*)cookie) != 0)
        goto done;

    ret = 0;

done:
    pthread_attr_destroy(&attr);
    LEAVE;
    return ret;
}

int posix_gettid_ocall(void)
{
    ENTER;
    int ret = (int)syscall(SYS_gettid);
    LEAVE;
    return ret;
}

int posix_getpid_ocall(void)
{
    ENTER;
    int ret = (int)syscall(SYS_getpid);
    LEAVE;
    return ret;
}

int posix_nanosleep_ocall(
    const struct posix_timespec* req,
    struct posix_timespec* rem)
{
    ENTER;
    int ret;

    if ((ret = nanosleep((struct timespec*)req, (struct timespec*)rem)) != 0)
        ret = -errno;

    LEAVE;
    return ret;
}

int posix_wait_ocall(
    int* host_uaddr,
    const struct posix_timespec* timeout)
{
    ENTER;
    int retval = 0;

    if (__sync_fetch_and_add(host_uaddr, -1) == 0)
    {
            retval = (int)syscall(
                SYS_futex,
                host_uaddr,
                FUTEX_WAIT_PRIVATE,
                -1,
                timeout,
                NULL,
                0);

        if (retval != 0)
            retval = -errno;
    }

    LEAVE;
    return retval;
}

void posix_wake_ocall(int* host_uaddr)
{
    ENTER;

    if (__sync_fetch_and_add(host_uaddr, 1) != 0)
    {
        syscall(SYS_futex, host_uaddr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    }

    LEAVE;
}

int posix_wake_wait_ocall(
    int* waiter_host_uaddr,
    int* self_host_uaddr,
    const struct posix_timespec* timeout)
{
    ENTER;

    posix_wake_ocall(waiter_host_uaddr);
    int ret = posix_wait_ocall(self_host_uaddr, timeout);

    LEAVE;
    return ret;
}

int posix_clock_gettime_ocall(int clk_id, struct posix_timespec* tp)
{
    ENTER;
    int ret = clock_gettime(clk_id, (struct timespec*)tp);
    LEAVE;
    return ret;
}

int posix_tkill_ocall(int tid, int sig)
{
    ENTER;
#if 1
    printf("%s(TID=%d, tid=%d, sig=%d)\n",
        __FUNCTION__, posix_gettid(), tid, sig);
    fflush(stdout);
#endif

    posix_lock_kill();
    long r = syscall(SYS_tkill, tid, sig);
    posix_unlock_kill();

    //sleep_msec(1000);

    if (r != 0)
    {
        LEAVE;
        return -errno;
    }

    LEAVE;
    return 0;
}

/* ATTN: duplicate of OE definition */
typedef struct _host_exception_context
{
    /* exit code */
    uint64_t rax;

    /* tcs address */
    uint64_t rbx;

    /* exit address */
    uint64_t rip;
} oe_host_exception_context_t;

/* ATTN: duplicate of OE definition */
uint64_t oe_host_handle_exception(
    oe_host_exception_context_t* context,
    uint64_t arg);

OE_STATIC_ASSERT(sizeof(struct posix_siginfo) == sizeof(siginfo_t));
OE_STATIC_ASSERT(sizeof(struct posix_ucontext) == sizeof(ucontext_t));
OE_STATIC_ASSERT(sizeof(struct posix_siginfo) == sizeof(siginfo_t));
OE_STATIC_ASSERT(sizeof(struct posix_sigset) == sizeof(sigset_t));

#define ENCLU_ERESUME 3
extern uint64_t OE_AEP_ADDRESS;

int posix_print_backtrace(void)
{
    void* buffer[64];

    int n = backtrace(buffer, sizeof(buffer));

    if (n <= 1)
        return -1;

    char** syms = backtrace_symbols(buffer, n);

    if (!syms)
        return -1;

    printf("=== posix_print_backtrace()\n");

    for (int i = 0; i < n; i++)
        printf("%s\n", syms[i]);

    free(syms);

    fflush(stdout);

    return 0;
}

static void _set_sig_args(
    int enclave_sig,
    int sig,
    siginfo_t* si,
    ucontext_t* uc)
{
    struct posix_sig_args* args = &__posix_shared_block->sig_args;

    memset(args, 0, sizeof(struct posix_sig_args));
    args->enclave_sig = enclave_sig,
    args->sig = sig;
    args->siginfo = *(struct posix_siginfo*)si;
    args->ucontext = *(struct posix_ucontext*)uc;
}

static void _posix_host_signal_handler(int sig, siginfo_t* si, ucontext_t* uc)
{
    /* Build the host exception context */
    oe_host_exception_context_t hec = {0};
    hec.rax = (uint64_t)uc->uc_mcontext.gregs[REG_RAX];
    hec.rbx = (uint64_t)uc->uc_mcontext.gregs[REG_RBX];
    hec.rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];

    /* If the signal originated within the enclave */
    if (hec.rax == ENCLU_ERESUME && hec.rip == OE_AEP_ADDRESS)
    {
#if 1
        fprintf(stderr, "*** ENCLAVE.SIGNAL: tid=%d sig=%d\n",
            posix_gettid(), sig);
        fflush(stderr);
#endif

        uint64_t action = oe_host_handle_exception(&hec, POSIX_SIGACTION);

        if (action == OE_EXCEPTION_CONTINUE_EXECUTION)
        {
            _set_sig_args(true, sig, si, uc);
            return;
        }

        fprintf(stderr, "unhanlded signal: %d\n", sig); fflush(stderr);
        abort();
    }
    else
    {
#if 1
        fprintf(stderr, "*** HOST.SIGNAL: tid=%d sig=%d\n",
            posix_gettid(), sig);
        fflush(stderr);
#endif

        _set_sig_args(false, sig, si, uc);
        return;
    }
}

int posix_rt_sigaction_ocall(
    int signum,
    const struct posix_sigaction* pact,
    size_t sigsetsize)
{
    ENTER;
    struct posix_sigaction act = *pact;
    extern void posix_restore(void);

#if 0
    printf("%s(tid=%d, signum=%d)\n",
        __FUNCTION__, posix_gettid(), signum);
    fflush(stdout);
#endif

    errno = 0;

    act.handler = (uint64_t)_posix_host_signal_handler;
    act.restorer = (uint64_t)posix_restore;

    long r = syscall(SYS_rt_sigaction, signum, &act, NULL, sigsetsize);

    if (r != 0)
    {
        LEAVE;
        return -errno;
    }

    LEAVE;
    return 0;
}

void posix_dump_sigset(const char* msg, const posix_sigset* set)
{
    printf("%s: ", msg);

    for (int i = 0; i < NSIG; i++)
    {
        if (sigismember((sigset_t*)set, i))
            printf("%d ", i);
    }

    printf("\n");
    fflush(stdout);

}

int posix_rt_sigprocmask_ocall(
    int how,
    const struct posix_sigset* set,
    struct posix_sigset* oldset,
    size_t sigsetsize)
{
    ENTER;
#if 0
    const char* howstr;

    switch (how)
    {
        case SIG_BLOCK:
            howstr = "block";
            break;
        case SIG_UNBLOCK:
            howstr = "unblock";
            break;
        case SIG_SETMASK:
            howstr = "setmask";
            break;
        default:
            howstr = "unknown";
            break;
    }

    printf("posix_rt_sigprocmask_ocall(how=%s, tid=%d)\n",
        howstr, posix_gettid());

    posix_dump_sigset(howstr, set);
#endif

    long r = syscall(SYS_rt_sigprocmask, how, set, oldset, sigsetsize);
    LEAVE;
    return r == 0 ? 0 : -errno;
}

void posix_noop_ocall(void)
{
//    ENTER;
//    LEAVE;
}

ssize_t posix_write_ocall(int fd, const void* data, size_t size)
{
    ssize_t ret = -1;

    ENTER;
    posix_unlock_kill();

    if (size == 0)
    {
        ret = 0;
        goto done;
    }

    if (fd == STDOUT_FILENO)
    {
        if (fwrite(data, 1, size, stdout) != size)
            goto done;

        fflush(stdout);
        ret = (ssize_t)size;
    }
    else if (fd == STDERR_FILENO)
    {
        if (fwrite(data, 1, size, stderr) != size)
            goto done;

        fflush(stderr);
        ret = (ssize_t)size;
    }

done:

    posix_lock_kill();
    LEAVE;
    return ret;
}
