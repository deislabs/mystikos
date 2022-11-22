#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <myst/backtrace.h>
#include <myst/config.h>
#include <myst/eraise.h>
#include <myst/fsgs.h>
#include <myst/kernel.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/signal.h>
#include <myst/stack.h>
#include <myst/time.h>

/* the size of red zone in bytes */
#define MYST_X86_64_ABI_REDZONE_SIZE 0x80

// #define TRACE

#define MYST_SIG_UNBLOCKED(mask) \
    (~mask) | ((uint64_t)1 << (SIGKILL - 1)) | ((uint64_t)1 << (SIGSTOP - 1));

static int _check_signum(unsigned signum)
{
    return (signum <= 0 || signum >= NSIG) ? -EINVAL : 0;
}

static uint64_t _sigset_to_uint64(const sigset_t* set)
{
    uint64_t* p = (uint64_t*)set;
    return *p;
}

static void _uint64_to_sigset(uint64_t val, sigset_t* set)
{
    uint64_t* p = (uint64_t*)set;
    *p = val;
}

MYST_INLINE
bool _is_on_altstack(stack_t* altstack, uint64_t rsp)
{
    uint64_t altstack_start = (uint64_t)altstack->ss_sp;
    uint64_t altstack_end = altstack_start + altstack->ss_size;

    return (rsp && rsp > altstack_start && rsp < altstack_end);
}

struct _handler_wrapper_arg
{
    // A signal handler can take either 3 parameters (with sigaction_t)
    // or just one (with signum), but not both. Only one of signum_handler
    // and sigaction_handler is non-null.
    sigaction_handler_t signum_handler;
    sigaction_function_t sigaction_handler;
    unsigned signum;
    siginfo_t* siginfo;
    ucontext_t* ucontext;
    mcontext_t* mcontext;
};

// Work around the limitation that myst_call_on_stack only allows
// one function parameter.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
long _handler_wrapper(void* arg_)
{
    struct _fpstate fpregs __attribute__((aligned(16))) = {0};
    struct _handler_wrapper_arg arg = {0};
    ucontext_t ucontext = {0};
    siginfo_t siginfo = {0};

    /* If sigaltstack is enabled, the original arguments will be saved
     * on the OE altstack and could be overwritten if nested exceptions
     * occur. To avoid such issues, we make a copy of necessary arguments
     * on the local stack. */

    assert(arg_);
    arg = *(struct _handler_wrapper_arg*)arg_;

    if (arg.siginfo)
        siginfo = *(arg.siginfo);

    if (arg.ucontext)
        ucontext = *(arg.ucontext);

    if (arg.mcontext)
    {
        ucontext.uc_mcontext = *(arg.mcontext);
        /* do not copy the padding which could contain the information of
         * extended xstate (if present) in the Linux target to match behavior of
         * OE (always clear padding during the enclave entry) */
        memcpy(
            &fpregs,
            arg.mcontext->fpregs,
            sizeof(struct _fpstate) - sizeof(((struct _fpstate*)0)->padding));
        ucontext.uc_mcontext.fpregs = &fpregs;
    }

    if (arg.sigaction_handler)
    {
        assert(arg.signum_handler == NULL);
        arg.sigaction_handler(arg.signum, &siginfo, &ucontext);
    }
    else
    {
        assert(arg.signum_handler != NULL);
        arg.signum_handler(arg.signum);
    }

    myst_signal_restore_mask();

    if (arg.mcontext)
    {
        /* The signal handler in the programming language runtime or the
         * application might not return. If execution returns here, set the CPU
         * context as the returned mcontext to continue execution. */
        myst_sigreturn(&(ucontext.uc_mcontext));

        /* Unreachable */
        assert(0);
    }

    return 0;
}
#pragma GCC diagnostic pop

/* Called to make sure we have a clean sigactions structure.
 * This is called from the main process creation where there will be no
 * handlers, so a clean structure needed. It is called from clone for creating a
 * new process, where we will need to allocate a new structure for the new
 * process. The clone will then copy the parent process handlers across. It is
 * called from exec in order to make sure we have a structure and it is cleaned
 * out as the new exec-ed process has no handlers by default.
 */
int myst_signal_init(myst_process_t* process)
{
    int ret = 0;

    if (!process->signal.sigactions)
    {
        process->signal.sigactions = calloc(NSIG, sizeof(posix_sigaction_t));

        if (process->signal.sigactions == NULL)
            ERAISE(-ENOMEM);
    }
    else
    {
        memset(process->signal.sigactions, 0, NSIG * sizeof(posix_sigaction_t));
    }

done:
    return ret;
}

void myst_signal_free(myst_process_t* process)
{
    sigset_t block_all;

    // Block all signals from this point. Not that there are a couple of
    // none-blocking signals, but that delivery scenario will ignore it because
    // sigactions is NULL
    memset(&block_all, -1, sizeof(block_all));
    myst_signal_sigprocmask(SIG_BLOCK, &block_all, NULL);

    free(process->signal.sigactions);
    process->signal.sigactions = NULL;
}

long myst_signal_sigaction(
    unsigned signum,
    const posix_sigaction_t* new_action,
    posix_sigaction_t* old_action)
{
    long ret = 0;
    ECHECK(_check_signum(signum));

    if (signum == SIGKILL || signum == SIGSTOP)
        ERAISE(-EINVAL);

    myst_process_t* process = myst_process_self();
    assert(process->signal.sigactions);

    // Sigactions are shared process-wide. We need to ensure
    // no simultaneous updates from multiple threads.
    myst_spin_lock(&process->signal.lock);

    if (old_action)
        *old_action = process->signal.sigactions[signum - 1];

    if (new_action)
    {
        myst_thread_t* thread = myst_thread_self();
        if (signum == SIGSEGV)
        {
            if (new_action->flags & SA_ONSTACK)
            {
                /* hint OE to use the signal delivery altstack with #PF */
                myst_tcall_td_register_exception_handler_stack(
                    (void*)thread->target_td, 0x5 /* PAGE_FAULT */);
            }
            else
            {
                /* hint OE not to use the signal delivery altstack with #PF */
                myst_tcall_td_unregister_exception_handler_stack(
                    (void*)thread->target_td, 0x5 /* PAGE_FAULT */);
            }
        }

        process->signal.sigactions[signum - 1] = *new_action;
    }

    myst_spin_unlock(&process->signal.lock);

done:
    return ret;
}

long myst_signal_sigprocmask(int how, const sigset_t* set, sigset_t* oldset)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    if (oldset != NULL)
    {
        _uint64_to_sigset(thread->signal.mask, oldset);
    }

    if (how != SIG_SETMASK && how != SIG_BLOCK && how != SIG_UNBLOCK)
        ERAISE(-EINVAL);

    if (set != NULL)
    {
        uint64_t mask = _sigset_to_uint64(set);
        if (how == SIG_SETMASK)
            thread->signal.mask = mask;
        else if (how == SIG_BLOCK)
            thread->signal.mask |= mask;
        else if (how == SIG_UNBLOCK)
            thread->signal.mask &= ~mask;

        /* keep the copy of mask */
        thread->signal.original_mask = thread->signal.mask;
    }

done:
    return ret;
}

void myst_signal_free_siginfos(myst_thread_t* thread)
{
    for (int i = 0; i < NSIG - 1; i++)
    {
        if (thread->signal.siginfos[i])
        {
            for (struct siginfo_list_item* p = thread->signal.siginfos[i]; p;)
            {
                struct siginfo_list_item* next = p->next;
                if (p->siginfo)
                {
                    free(p->siginfo);
                    p->siginfo = NULL;
                }
                free(p);
                p = next;
            }
        }
        thread->signal.siginfos[i] = NULL;
    }
}

const char* myst_signum_to_string(unsigned signum)
{
    switch (signum)
    {
        case 1:
            return "SIGHUP";
        case 2:
            return "SIGINT";
        case 3:
            return "SIGQUIT";
        case 4:
            return "SIGILL";
        case 5:
            return "SIGTRAP";
        case 6:
            return "SIGABRT/SIGIOT";
        case 7:
            return "SIGBUS";
        case 8:
            return "SIGFPE";
        case 9:
            return "SIGKILL";
        case 10:
            return "SIGUSR1";
        case 11:
            return "SIGSEGV";
        case 12:
            return "SIGUSR2";
        case 13:
            return "SIGPIPE";
        case 14:
            return "SIGALRM";
        case 15:
            return "SIGTERM";
        case 16:
            return "SIGSTKFLT";
        case 17:
            return "SIGCHLD";
        case 18:
            return "SIGCONT";
        case 19:
            return "SIGSTOP";
        case 20:
            return "SIGTSTP";
        case 21:
            return "SIGTTIN";
        case 22:
            return "SIGTTOU";
        case 23:
            return "SIGURG";
        case 24:
            return "SIGXCPU";
        case 25:
            return "SIGXFSZ";
        case 26:
            return "SIGVTALRM";
        case 27:
            return "SIGPROF";
        case 28:
            return "SIGWINCH";
        case 29:
            return "SIGIO/SIGPOLL";
        case 30:
            return "SIGPWR";
        case 31:
            return "SIGSYS";
        default:
            return "unknown";
    }
}

static bool _is_signal_terminal(unsigned signum)
{
    switch (signum)
    {
        case SIGHUP:
        case SIGINT:
        case SIGQUIT:
        case SIGILL:
        case SIGABRT:
        case SIGFPE:
        case SIGKILL:
        case SIGSEGV:
        case SIGPIPE:
        case SIGALRM:
        case SIGTERM:
        case SIGUSR1:
        case SIGUSR2:
            return true;
        default:
            return false;
    }
}

// No/default signal disposition specified, use the default action. See
// https://man7.org/linux/man-pages/man7/signal.7.html for details.
static long _default_signal_handler(unsigned signum)
{
    if (__myst_kernel_args.strace_config.trace_syscalls ||
        __myst_kernel_args.trace_errors)
        myst_eprintf(
            "*** Terminating signal %u (%s): pid=%d tid=%d\n",
            signum,
            myst_signum_to_string(signum),
            myst_getpid(),
            myst_gettid());

    myst_assume(
        signum != SIGCHLD && signum != SIGCONT && signum != SIGSTOP &&
        signum != SIGURG && signum != SIGWINCH);

    myst_thread_t* thread = myst_thread_self();
    myst_process_t* process = myst_process_self();
    myst_thread_t* process_thread = process->main_process_thread;

    bool process_status_set = false;
    if (__atomic_compare_exchange_n(
            &process->exit_status_signum_set,
            &process_status_set,
            true,
            false,
            __ATOMIC_RELEASE,
            __ATOMIC_ACQUIRE))
    {
        process->exit_status = 128 + signum;
        process->terminating_signum = signum;
    }

    // If the main thread has not been sent signal or has not exited already
    // forward this exception to the main thread to cause the whole process to
    // exit with this signal
    if ((thread != process_thread) && (signum != SIGKILL) &&
        _is_signal_terminal(signum))
    {
        enum myst_thread_status expected = MYST_RUNNING;
        if (__atomic_compare_exchange_n(
                &thread->thread_status,
                &expected,
                MYST_KILLED,
                false,
                __ATOMIC_RELEASE,
                __ATOMIC_ACQUIRE))
        {
            myst_signal_deliver(process_thread, signum, NULL);
            if (process_thread->signal.waiting_on_event)
            {
                myst_tcall_wake(process_thread->event);
            }
        }
    }
    else if (thread == process_thread)
    {
        // Make sure all other threads are shutdown properly.
        // This is usually initiated via a process call to exit() or _Exit().
        // If we are here then there is a good chance it was not called
        myst_kill_thread_group();

        thread->thread_status = MYST_KILLED;
    }

    myst_longjmp(&thread->jmpbuf, 1);

    // Unreachable
    assert(0);
    return 0;
}

static void _print_bytes(unsigned char* addr)
{
    unsigned char* end = addr + 16;
    if (myst_is_addr_within_mman_region(end))
    {
        myst_eprintf("16 bytes from %p: \n", addr);
        myst_eprintf(
            "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
            "%02x %02x %02x\n",
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            addr[4],
            addr[5],
            addr[6],
            addr[7],
            addr[8],
            addr[9],
            addr[10],
            addr[11],
            addr[12],
            addr[13],
            addr[14],
            addr[15]);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wstack-usage=1216"
/* ATTN: fix this to not use so much stack space */
static long _handle_one_signal(
    unsigned signum,
    siginfo_t* siginfo,
    mcontext_t* mcontext)
{
    long ret = 0;
    ucontext_t context;

    /* save the original fsbase */
    void* original_fsbase = myst_get_fsbase();
    void* gsbase = myst_get_gsbase();

    /* Switch to kernel fsbase if needed. printf statements in this function are
     * downcalls to OE, which checks for FS == GS invariant in some places */
    if (original_fsbase != gsbase)
        myst_set_fsbase(gsbase);

#ifdef TRACE
    printf(
        "%s(%u %s) pid=%d tid=%d\n",
        __FUNCTION__,
        signum,
        myst_signum_to_string(signum),
        myst_getpid(),
        myst_gettid());
#endif

    // Caution: This function should not allocate memory since the signal
    // handler may not return due to a long jump.

    ECHECK(_check_signum(signum));

    // use a zeroed ucontext_t. If the caller passed in a mcontext
    // (register states), we only set up the uc_mcontext during
    // _handler_wrapper to avoid doing an extra memory copy here.
    // Note we modified pthread_cancel in MUSL to avoid the dependency
    // on mcontext.
    memset(&context, 0, sizeof(context));

    myst_thread_t* thread = myst_thread_self();
    myst_process_t* process = myst_process_self();

    uint64_t mask = (uint64_t)1 << (signum - 1);

    // Both the child and process thread should point to array of sigactions.
    // The only exception to this is during shutdown. All signals that can be
    // blocked have been, but the non-blocking signals may still get through so
    // we ignore then
    if (process->signal.sigactions == NULL)
    {
        return 0;
    }

    posix_sigaction_t* action = &process->signal.sigactions[signum - 1];
    if (action->handler == (uint64_t)SIG_DFL)
    {
        // Some signals are ignored completely, so only call handler if it is
        // not ignored
        if (signum != SIGCHLD && signum != SIGCONT && signum != SIGSTOP &&
            signum != SIGURG && signum != SIGWINCH)
        {
            // call the internal thread handlers if present to do any cleanup
            // before calling the default signal handler which terminates the
            // thread
            myst_thread_sig_handler_t* thread_sig_handler =
                thread->signal.thread_sig_handler;
            while (thread_sig_handler)
            {
                thread_sig_handler->signal_fn(
                    signum, thread_sig_handler->signal_fn_arg);
                thread_sig_handler = thread_sig_handler->previous;
            }

            // Print out backtrace for segfault exception
            // Current myst_backtrace implementation only supports printing
            // stacktrace for kernel stacks, so we check for that upfront.
            if (signum == SIGSEGV &&
                myst_within_stack((void**)mcontext->gregs[REG_RBP]))
            {
                void* buf = calloc(1, 1024);
                size_t ret = 0;

                myst_eprintf("*** Kernel segmentation fault \n");
                if ((ret = myst_backtrace3(
                         (void**)mcontext->gregs[REG_RBP], buf, sizeof(buf))) >
                    0)
                {
                    myst_dump_backtrace(buf, ret);
                }
                free(buf);
            }

            // call the default terminating signal handler
            ret = _default_signal_handler(signum);
        }
    }
    else if (action->handler == (uint64_t)SIG_IGN)
    {
        if (__myst_kernel_args.strace_config.trace_syscalls ||
            __myst_kernel_args.trace_errors)
        {
            myst_eprintf(
                "*** Ignoring signal %u (%s): pid=%d tid=%d\n",
                signum,
                myst_signum_to_string(signum),
                myst_getpid(),
                myst_gettid());
        }
        ret = 0;
        /* Restore fsbase to value at function entry */
        myst_set_fsbase(original_fsbase);
    }
    else
    {
        bool use_alt_stack = false;
        bool is_on_alt_stack = false;
        struct _handler_wrapper_arg arg = {0};

        if (__myst_kernel_args.strace_config.trace_syscalls ||
            __myst_kernel_args.trace_errors)
        {
            myst_eprintf(
                "*** Delivering signal to app signal handler %u (%s): pid=%d "
                "tid=%d\n",
                signum,
                myst_signum_to_string(signum),
                myst_getpid(),
                myst_gettid());

            if (signum == SIGSEGV)
            {
                myst_eprintf(
                    "Exception register mcontext state: rbp=%llx rsp=%llx "
                    "rip=%llx\n",
                    mcontext->gregs[REG_RBP],
                    mcontext->gregs[REG_RSP],
                    mcontext->gregs[REG_RIP]);

                if (siginfo->si_addr &&
                    myst_is_addr_within_mman_region((void*)siginfo->si_addr))
                    _print_bytes((unsigned char*)siginfo->si_addr);

                if (mcontext->gregs[REG_RIP] &&
                    myst_is_addr_within_mman_region(
                        (void*)mcontext->gregs[REG_RIP]))
                    _print_bytes((unsigned char*)mcontext->gregs[REG_RIP]);

                myst_eprintf(
                    "*** Signal SIGSEGV: si_code: %d si_addr: %p pid=%d "
                    "tid=%d\n",
                    siginfo->si_code,
                    siginfo->si_addr,
                    myst_getpid(),
                    myst_gettid());
            }
        }

        // Print out backtrace for segfault exception
        // Current myst_backtrace implementation only supports printing
        // stacktrace for kernel stacks, so we check for that upfront.
        if (signum == SIGSEGV &&
            myst_within_stack((void**)mcontext->gregs[REG_RBP]))
        {
            void* buf = calloc(1, 1024);
            size_t ret = 0;

            myst_eprintf("*** Kernel segmentation fault \n");
            if ((ret = myst_backtrace3(
                     (void**)mcontext->gregs[REG_RBP], buf, sizeof(buf))) > 0)
            {
                myst_dump_backtrace(buf, ret);
            }
            free(buf);
        }

        // add mask specified in action->sa_mask
        thread->signal.mask |= action->mask;
        if ((action->flags & SA_NODEFER) == 0)
            thread->signal.mask |= mask;

        // ATTN: handle other signal flags, e.g., SA_NOCLDSTOP, SA_NOCLDWAIT,
        // SA_RESETHAND, SA_RESTART, etc.

        stack_t* altstack = &thread->signal.altstack;
        uint64_t rsp_before_signal = 0;

        /* restore the user-space fsbase, which is pthread_self() */
        myst_set_fsbase(thread->crt_td);

        /* get the rsp value used to determine whether the context before
         * signal was on the alternative stack
         * a. for the case of non-delayed exception (mcontext is not NULL),
         *    use the rsp value from mcontext.
         * b. for the case of delayed exception (invoked during syscall),
         *    use the rsp value before switching to the kernel stack. */
        if (mcontext)
            rsp_before_signal = mcontext->gregs[REG_RSP];
        else
            rsp_before_signal = thread->user_rsp;

        /* ensure rsp_before_signal is set */
        if (!rsp_before_signal)
            myst_panic(
                "invalid rsp for calling signal handler: 0x%lx",
                rsp_before_signal);

        /* If the thread is already on the alternative stack, set
         * use_alt_stack to false even if SA_ONSTACK flag is set.
         * Doing so avoids the nested signal handler starts from the
         * top of the alternative stack */

        is_on_alt_stack = _is_on_altstack(altstack, rsp_before_signal);

        use_alt_stack = (action->flags & SA_ONSTACK) &&
                        !(altstack->ss_flags & SS_DISABLE) &&
                        !is_on_alt_stack && (altstack->ss_sp != 0);

        if (mcontext)
            arg.mcontext = mcontext;

        if ((action->flags & SA_SIGINFO) != 0)
        {
            arg.sigaction_handler = (sigaction_function_t)(action->handler);
            arg.signum = signum;
            arg.siginfo = siginfo;
            arg.ucontext = &context;
        }
        else
        {
            arg.signum_handler = (sigaction_handler_t)(action->handler);
            arg.signum = signum;
        }

        if (use_alt_stack)
        {
            uint64_t stacktop = (uint64_t)altstack->ss_sp + altstack->ss_size;

            // pass stack limits if using alternate stack.
            // dotnet runtime uses the uc_stack field to detect if its running
            // on an alternate stack.
            if ((action->flags & SA_SIGINFO) != 0)
            {
                context.uc_stack.ss_sp = altstack->ss_sp;
                context.uc_stack.ss_size = altstack->ss_size;
                context.uc_stack.ss_flags = altstack->ss_flags;
            }

            myst_call_on_stack((void*)stacktop, _handler_wrapper, &arg);
        }
        else if (mcontext && !is_on_alt_stack)
        {
            /* in the case of non-delayed exceptions occur not on the
             * alternative stack, continue with current stack */
            _handler_wrapper(&arg);
        }
        else
        {
            /* for the other cases, we call the _handler_wrapper on the
             * stack frame before entering the signal handler. This can be
             * either the stack frame (within the alternative stack) where
             * the exception occurs or the stack frame before entering the
             * syscall layer. Doing so ensures that we do not run the user
             * handler on kernel stack. */
            uint64_t stacktop =
                (rsp_before_signal & -16) - MYST_X86_64_ABI_REDZONE_SIZE;

            myst_call_on_stack((void*)stacktop, _handler_wrapper, &arg);
        }

        /* if the user handler returns, restore the fsbase to the value before
         * calling the handler */
        myst_set_fsbase(original_fsbase);
    }

done:

    return ret;
}
#pragma GCC diagnostic pop

void _myst_sigstop_block(myst_process_t* process)
{
    __sync_val_compare_and_swap(&process->sigstop_futex, 0, 1);
}

void _myst_sigstop_unblock(myst_process_t* process)
{
    if (__sync_val_compare_and_swap(&process->sigstop_futex, 1, 0) == 1)
        myst_futex_wake(
            &process->sigstop_futex, INT_MAX, FUTEX_BITSET_MATCH_ANY);
}

void _myst_sigstop_wait(void)
{
    myst_process_t* process = myst_process_self();

    while (process->sigstop_futex == 1)
    {
        long ret = myst_futex_wait(
            &process->sigstop_futex, 1, NULL, FUTEX_BITSET_MATCH_ANY);
        if ((ret < 0) && (ret != -EAGAIN))
            break;
    }
}

int myst_signal_has_active_signals(myst_thread_t* thread)
{
    uint64_t unblocked = MYST_SIG_UNBLOCKED(thread->signal.mask);
    uint64_t active_signals = thread->signal.pending & unblocked;
    return active_signals != 0;
}

long myst_signal_process(myst_thread_t* thread)
{
    /* If we are waiting due to sigstop then block now */
    _myst_sigstop_wait();

    myst_spin_lock(&thread->signal.lock);

    // Active signals are the ones that are both unblocked and pending.
    // Note SIGKILL and SIGSTOP can never be blocked.
    uint64_t unblocked = MYST_SIG_UNBLOCKED(thread->signal.mask);
    uint64_t active_signals = thread->signal.pending & unblocked;

    while (active_signals != 0)
    {
        unsigned bitnum = __builtin_ctzl(active_signals);

        while (thread->signal.siginfos[bitnum])
        {
            // Create a local copy and free the global one.
            siginfo_t local_siginfo = {0};
            siginfo_t* siginfo = NULL;
            struct siginfo_list_item* next =
                thread->signal.siginfos[bitnum]->next;

            if (thread->signal.siginfos[bitnum]->siginfo)
            {
                local_siginfo = *(thread->signal.siginfos[bitnum]->siginfo);
                siginfo = &local_siginfo;

                free(thread->signal.siginfos[bitnum]->siginfo);
            }
            free(thread->signal.siginfos[bitnum]);
            thread->signal.siginfos[bitnum] = next;

            myst_spin_unlock(&thread->signal.lock);

            // Signal numbers are 1 based.
            unsigned signum = bitnum + 1;
            _handle_one_signal(signum, siginfo, NULL);

            myst_spin_lock(&thread->signal.lock);
        }

        // Clear the bit from the active signals. We are ready for the next.
        active_signals &= ~((uint64_t)1 << bitnum);
        // Clear the pending bit.
        thread->signal.pending &= ~((uint64_t)1 << bitnum);
    }
    myst_spin_unlock(&thread->signal.lock);
    return 0;
}

long myst_signal_deliver(
    myst_thread_t* thread,
    unsigned signum,
    siginfo_t* siginfo)
{
    long ret = 0;
    struct siginfo_list_item* new_item = NULL;
    myst_process_t* process = thread->process;
    uint64_t handler = 0;

    if (process->signal.sigactions)
        handler = process->signal.sigactions[signum - 1].handler;

#ifdef TRACE
    printf(
        "%s(%u %s) from: pid=%d tid=%d to: pid=%d tid=%d\n",
        __FUNCTION__,
        signum,
        myst_signum_to_string(signum),
        myst_getpid(),
        myst_gettid(),
        thread->process->pid,
        thread->tid);
#endif

    ECHECK(_check_signum(signum));

    /* SIGSTOP and SIGCONT may be sent from another process but they need to be
     * processed when they are being delivered, not when a thread is processing
     * it */
    if (signum == SIGSTOP)
    {
        /* set the SIGSTOP block for the process */
        _myst_sigstop_block(thread->process);
        return 0;
    }
    else if (signum == SIGCONT)
    {
        /* release the SIGSTOP block for the process */
        _myst_sigstop_unblock(thread->process);
    }

    uint64_t mask = (uint64_t)1 << (signum - 1);

    /* Deliver signal if
     * 1. signal is SIGKILL, or
     * 2. handler is not SIG_DFL and signal is not one of [SIGCHLD, SIGCONT,
     * SIGSTOP, SIGURG, SIGWINCH], and
     * 3. handler is not SIG_IGN
     */
    if (signum == SIGKILL ||
        (!(handler == (uint64_t)SIG_DFL &&
           (signum == SIGCHLD || signum == SIGCONT || signum == SIGSTOP ||
            signum == SIGURG || signum == SIGWINCH)) &&
         handler != (uint64_t)SIG_IGN))
    {
        new_item = calloc(1, sizeof(struct siginfo_list_item));
        if (new_item == NULL)
        {
            ret = -ENOMEM;
            goto done;
        }
        new_item->siginfo = siginfo;

        // Multiple threads could be trying to deliver a signal
        // to this thread simultaneously. Protect with a lock.
        myst_spin_lock(&thread->signal.lock);

        if (thread->signal.siginfos[signum - 1] == NULL)
        {
            thread->signal.siginfos[signum - 1] = new_item;
        }
        else
        {
            struct siginfo_list_item* ptr = thread->signal.siginfos[signum - 1];
            while (ptr->next != NULL)
                ptr = ptr->next;
            ptr->next = new_item;
        }
        thread->signal.pending |= mask;
        siginfo = NULL;
        new_item = NULL;

        myst_spin_unlock(&thread->signal.lock);

        // If this event is not being blocked, wake up the necessary threads */
        if ((!(thread->signal.mask & mask)) || (signum == SIGKILL))
        {
            // Wake up target if necessary
            if (thread->signal.waiting_on_event)
            {
#ifdef TRACE
                printf("thread sleeping on thread->event futex. Waking up "
                       "thread..\n");
#endif
                myst_tcall_wake(thread->event);
            }

#if (MYST_INTERRUPT_WITH_SIGNAL == 1)
            /* Wake up the thread if blocked in the target */
            myst_interrupt_thread(thread);
#elif (MYST_INTERRUPT_WITH_SIGNAL == -1)
            /* Make sure any polls get woken up to process any outstanding
             * events */
            myst_tcall_poll_wake();
#else
#error "MYST_INTERRUPT_WITH_SIGNAL undefined"
#endif
        }
    }

    if (!__sync_val_compare_and_swap(&thread->pause_futex, 0, 1))
    {
        ret = myst_futex_wake(&thread->pause_futex, 1, FUTEX_BITSET_MATCH_ANY);
        // Expect ret == 1, otherwise, return error
        if (ret == 1)
            ret = 0;
    }

done:
    if (siginfo)
        free(siginfo); // Free the siginfo object if not delivered.

    if (new_item)
        free(new_item); // free if allocated and not inserted

    return ret;
}

long myst_signal_sigpending(sigset_t* set, unsigned size)
{
    if (size > sizeof(sigset_t) || !set)
        return -EINVAL;

    memset(set, 0, size);

    myst_thread_t* thread = myst_thread_self();

    myst_thread_t* process_thread =
        myst_find_process(thread)->main_process_thread;

    assert(process_thread);

    // Union the pending signals targeted for the thread and process.
    _uint64_to_sigset(
        thread->signal.pending | process_thread->signal.pending, set);

    return 0;
}

long myst_signal_clone(
    myst_thread_t* parent_thread,
    myst_thread_t* child_thread)
{
    int ret = 0;
    ECHECK(myst_signal_init(child_thread->process));

    // Clone the signal dispositions
    unsigned len = (NSIG - 1) * sizeof(posix_sigaction_t);
    memcpy(
        child_thread->process->signal.sigactions,
        parent_thread->process->signal.sigactions,
        len);

    // Clone the signal mask
    child_thread->signal.mask = parent_thread->signal.mask;
    child_thread->signal.original_mask = parent_thread->signal.original_mask;

done:
    if (ret != 0)
    {
        free(child_thread->process->signal.sigactions);
        child_thread->process->signal.sigactions = NULL;
    }
    return ret;
}

void myst_handle_host_signal(siginfo_t* siginfo, mcontext_t* mcontext)
{
    assert(siginfo != NULL);
    assert(mcontext != NULL);

    _handle_one_signal(siginfo->si_signo, siginfo, mcontext);

    /* resume the execution based on mcontext for the unlikely case
     * where the _handle_one_signal returns (e.g., early return) */
    myst_sigreturn(mcontext);

    // Unreachable
    assert(0);
}

int myst_signal_altstack(const stack_t* ss, stack_t* old_ss)
{
    int ret = 0;
    myst_thread_t* me = myst_thread_self();

    if (old_ss != NULL)
    {
        *old_ss = me->signal.altstack;
        if (old_ss->ss_sp == 0)
            // Trying to be compatible with Linux. A never-installed
            // alt stack means it's disabled.
            old_ss->ss_flags |= SS_DISABLE;

        if (_is_on_altstack(old_ss, me->user_rsp))
            old_ss->ss_flags |= SS_ONSTACK;
    }

    if (ss != NULL)
    {
        // We don't support swapcontext in libc. No point
        // to support SS_AUTODISARM which was introduced to enable it.
        // The only flag allowed here is SS_DISABLE.
        if (ss->ss_flags & ~(SS_DISABLE) != 0)
            ERAISE(-EINVAL);

        if (_is_on_altstack(&me->signal.altstack, me->user_rsp))
            ERAISE(-EPERM);

        if (ss->ss_flags & SS_DISABLE)
        {
            me->signal.altstack.ss_flags |= SS_DISABLE;
            me->signal.altstack.ss_sp = NULL;
            me->signal.altstack.ss_size = 0;

            /* clear the signal delivery altstack */
            ECHECK(myst_clear_signal_delivery_altstack(me));
        }
        else
        {
            if (ss->ss_size < MINSIGSTKSZ)
                ERAISE(-ENOMEM);

            me->signal.altstack = *ss;

            /* set the signal delivery altstack if it was not set */
            if (!me->signal_delivery_altstack &&
                !me->signal_delivery_altstack_size)
                ECHECK(myst_set_signal_delivery_altstack(
                    me, MYST_THREAD_SIGNAL_DELIVERY_ALTSTACK_SIZE));
        }
    }

done:
    return ret;
}

void myst_signal_restore_mask(void)
{
    myst_thread_t* thread = myst_thread_self();

    /* restore the mask from orig_mask */
    thread->signal.mask = thread->signal.original_mask;
}
