#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/jump.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/jump.h>
#include "posix_signal.h"
#include "posix_ocalls.h"
#include "posix_ocall_structs.h"
#include "posix_io.h"
#include "posix_thread.h"
#include "posix_spinlock.h"
#include "posix_panic.h"
#include "posix_jump.h"
#include "posix_ocall_structs.h"
#include "posix_trace.h"
#include "posix_panic.h"

#include "pthread_impl.h"

/* */
#include "posix_warnings.h"

/* ATTN: handle SIG_IGN */
/* ATTN: handle SIG_DFL */

OE_STATIC_ASSERT(sizeof(sigset_t) == sizeof(posix_sigset_t));
OE_STATIC_ASSERT(sizeof(struct posix_siginfo) == sizeof(siginfo_t));
OE_STATIC_ASSERT(sizeof(struct posix_ucontext) == sizeof(ucontext_t));

static struct posix_sigaction _table[NSIG];
static posix_spinlock_t _lock;

typedef void (*sigaction_handler_t)(int, siginfo_t*, void*);

static void _get_sig_args(struct posix_sig_args* args, bool clear)
{
    posix_thread_t* self = posix_self();

    if (!args || !self || !self->shared_block)
        return;

    *args = self->shared_block->sig_args;

    if (clear)
        memset(&self->shared_block->sig_args, 0, sizeof(struct posix_sig_args));
}

static void _clear_sig_args(void)
{
    posix_thread_t* self = posix_self();

    if (!self || !self->shared_block)
    {
        POSIX_PANIC("unexpected");
    }

    memset(&self->shared_block->sig_args, 0, sizeof(struct posix_sig_args));
}

typedef void (*sigaction_function_t)(int, siginfo_t*, void*);

static __thread ucontext_t _thread_ucontext;

static void _enclave_signal_handler(void)
{
    struct posix_sig_args args;

    posix_unlock_kill();

    _get_sig_args(&args, true);

#if 1
    posix_printf("_enclave_signal_handler(): sig=%d\n", args.sig);
#endif

    posix_spin_lock(&_lock);
    uint64_t handler = _table[args.sig].handler;
    posix_spin_unlock(&_lock);

    if (!handler)
        POSIX_PANIC("unexpected");

    sigaction_function_t sigaction = (sigaction_function_t)handler;
    siginfo_t* si = (siginfo_t*)&args.siginfo;
    ucontext_t* uc = &_thread_ucontext;

    /* Invoke the sigacation funtion */
    (*sigaction)(args.sig, si, uc);

    /* Resume executation */
    {
        posix_jump_context_t ctx;

        ctx.rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
        ctx.rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
        ctx.rbp = (uint64_t)uc->uc_mcontext.gregs[REG_RBP];
        ctx.rbx = (uint64_t)uc->uc_mcontext.gregs[REG_RBX];
        ctx.r12 = (uint64_t)uc->uc_mcontext.gregs[REG_R12];
        ctx.r13 = (uint64_t)uc->uc_mcontext.gregs[REG_R13];
        ctx.r14 = (uint64_t)uc->uc_mcontext.gregs[REG_R14];
        ctx.r15 = (uint64_t)uc->uc_mcontext.gregs[REG_R15];

        if (!oe_is_within_enclave((void*)ctx.rip, sizeof(void*)))
            POSIX_PANIC("RIP is outside enclave");

        if (!oe_is_within_enclave((void*)ctx.rsp, sizeof(void*)))
            POSIX_PANIC("RSP is outside enclave");

        if (!oe_is_within_enclave((void*)ctx.rbp, sizeof(void*)))
            POSIX_PANIC("RBP is outside enclave");

        posix_jump(&ctx);
    }
}

extern uint64_t __oe_exception_arg;

static uint64_t _exception_handler(oe_exception_record_t* rec)
{
    posix_set_trace(22);

    if (__oe_exception_arg == POSIX_SIGACTION)
    {
        ucontext_t uc;

#if 0
        if (rec->context->rsp % 16)
            POSIX_PANIC("misaligned RSP");

        if (rec->context->rbp % 16)
            POSIX_PANIC("misaligned RBP");
#endif

        uc.uc_mcontext.gregs[REG_R8] = (int64_t)rec->context->r8;
        uc.uc_mcontext.gregs[REG_R9] = (int64_t)rec->context->r9;
        uc.uc_mcontext.gregs[REG_R10] = (int64_t)rec->context->r10;
        uc.uc_mcontext.gregs[REG_R11] = (int64_t)rec->context->r11;
        uc.uc_mcontext.gregs[REG_R12] = (int64_t)rec->context->r12;
        uc.uc_mcontext.gregs[REG_R13] = (int64_t)rec->context->r13;
        uc.uc_mcontext.gregs[REG_R14] = (int64_t)rec->context->r14;
        uc.uc_mcontext.gregs[REG_R15] = (int64_t)rec->context->r15;
        uc.uc_mcontext.gregs[REG_RDI] = (int64_t)rec->context->rdi;
        uc.uc_mcontext.gregs[REG_RSI] = (int64_t)rec->context->rsi;
        uc.uc_mcontext.gregs[REG_RBP] = (int64_t)rec->context->rbp;
        uc.uc_mcontext.gregs[REG_RBX] = (int64_t)rec->context->rbx;
        uc.uc_mcontext.gregs[REG_RDX] = (int64_t)rec->context->rdx;
        uc.uc_mcontext.gregs[REG_RAX] = (int64_t)rec->context->rax;
        uc.uc_mcontext.gregs[REG_RCX] = (int64_t)rec->context->rcx;
        uc.uc_mcontext.gregs[REG_RSP] = (int64_t)rec->context->rsp;
        uc.uc_mcontext.gregs[REG_RIP] = (int64_t)rec->context->rip;

        _thread_ucontext = uc;

        rec->context->rip = (uint64_t)_enclave_signal_handler;

        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }
    else
    {
        return OE_EXCEPTION_CONTINUE_SEARCH;
    }
}

void __posix_install_exception_handler(void)
{
    if (oe_add_vectored_exception_handler(false, _exception_handler) != OE_OK)
    {
        posix_printf("oe_add_vectored_exception_handler() failed\n");
        oe_abort();
    }
}

int posix_rt_sigaction(
    int signum,
    const struct posix_sigaction* act,
    struct posix_sigaction* oldact,
    size_t sigsetsize)
{
    int r;

    if (act)
    {
        if (act->handler == (uint64_t)0)
            POSIX_PANIC("unimplemented");

        if (act->handler == (uint64_t)1)
            POSIX_PANIC("unimplemented");
    }

    if (signum >= NSIG || !act)
        return -EINVAL;

    posix_spin_lock(&_lock);
    {
        if (oldact)
            *oldact = _table[signum];

        if (act)
            _table[signum] = *act;
    }
    posix_spin_unlock(&_lock);

    if (!act)
        return 0;

    if (posix_rt_sigaction_ocall(&r, signum, act, sigsetsize) != OE_OK)
        return -EINVAL;

    return r;
}

int posix_rt_sigprocmask(
    int how,
    const sigset_t* set,
    sigset_t* oldset,
    size_t sigsetsize)
{
    int retval;

    if (posix_rt_sigprocmask_ocall(
        &retval,
        how,
        (const struct posix_sigset*)set,
        (struct posix_sigset*)oldset,
        sigsetsize) != OE_OK)
    {
        return -EINVAL;
    }

    posix_dispatch_signal();
    return retval;
}

int posix_dispatch_signal(void)
{
    sigaction_handler_t handler;
    oe_jmpbuf_t env;
    struct posix_sig_args args;

    _get_sig_args(&args, false);

    if (args.sig == 0)
        return 0;

    if (args.enclave_sig)
        return 0;

    _clear_sig_args();

    /* Get the signal handler from the table */
    {
        posix_spin_lock(&_lock);
        handler = (sigaction_handler_t)_table[args.sig].handler;
        posix_spin_unlock(&_lock);

        if (!handler)
            POSIX_PANIC("handler not found");
    }

    /* Build a ucontext and invoke the signal handler */
    if (oe_setjmp(&env) == 0)
    {
        siginfo_t si;
        ucontext_t uc;

        memcpy(&si, &args.siginfo, sizeof(si));

        memset(&uc, 0, sizeof(uc));
        uc.uc_mcontext.gregs[REG_RSP] = (int64_t)env.rsp;
        uc.uc_mcontext.gregs[REG_RBP] = (int64_t)env.rbp;
        uc.uc_mcontext.gregs[REG_RIP] = (int64_t)env.rip;
        uc.uc_mcontext.gregs[REG_RBX] = (int64_t)env.rbx;
        uc.uc_mcontext.gregs[REG_R12] = (int64_t)env.r12;
        uc.uc_mcontext.gregs[REG_R13] = (int64_t)env.r13;
        uc.uc_mcontext.gregs[REG_R14] = (int64_t)env.r14;
        uc.uc_mcontext.gregs[REG_R15] = (int64_t)env.r15;

        /* Invoke the signal handler */
        handler(args.sig, &si, &uc);

        env.rsp = (uint64_t)uc.uc_mcontext.gregs[REG_RSP];
        env.rbp = (uint64_t)uc.uc_mcontext.gregs[REG_RBP];
        env.rip = (uint64_t)uc.uc_mcontext.gregs[REG_RIP];
        env.rbx = (uint64_t)uc.uc_mcontext.gregs[REG_RBX];
        env.r12 = (uint64_t)uc.uc_mcontext.gregs[REG_R12];
        env.r13 = (uint64_t)uc.uc_mcontext.gregs[REG_R13];
        env.r14 = (uint64_t)uc.uc_mcontext.gregs[REG_R14];
        env.r15 = (uint64_t)uc.uc_mcontext.gregs[REG_R15];

        oe_longjmp(&env, 1);
        POSIX_PANIC("unreachable");
    }

    /* control continues here if hanlder didn't change RIP */

    return 0;
}

extern struct posix_shared_block* __posix_init_shared_block;

void posix_lock_kill(void)
{
    if (__posix_init_shared_block)
    {
        posix_spin_lock(&__posix_init_shared_block->kill_lock);
    }
    else
    {
        POSIX_PANIC("unexpected");
    }
}

void posix_unlock_kill(void)
{
    if (__posix_init_shared_block)
    {
        posix_spin_unlock(&__posix_init_shared_block->kill_lock);
    }
    else
    {
        POSIX_PANIC("unexpected");
    }
}
