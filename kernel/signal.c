#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/fsgs.h>
#include <myst/printf.h>
#include <myst/signal.h>

//#define TRACE

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
};

// Work around the limitation that myst_call_on_stack only allows
// one function parameter.
long _handler_wrapper(void* arg_)
{
    struct _handler_wrapper_arg* arg = arg_;
    if (arg->sigaction_handler)
    {
        assert(arg->signum_handler == NULL);
        arg->sigaction_handler(arg->signum, arg->siginfo, arg->ucontext);
    }
    else
    {
        assert(arg->signum_handler != NULL);
        arg->signum_handler(arg->signum);
    }
    return 0;
}

int myst_signal_init(myst_process_t* process)
{
    int ret = 0;

    process->signal.sigactions = calloc(NSIG, sizeof(posix_sigaction_t));

    if (process->signal.sigactions == NULL)
        ERAISE(-ENOMEM);

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
        process->signal.sigactions[signum - 1] = *new_action;

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

// No/default signal disposition specified, use the default action. See
// https://man7.org/linux/man-pages/man7/signal.7.html for details.
static long _default_signal_handler(unsigned signum)
{
#if TRACE
    printf("%s(%u %s)\n", __FUNCTION__, signum, myst_signum_to_string(signum));
#endif

    if (signum == SIGCHLD || signum == SIGCONT || signum == SIGSTOP ||
        signum == SIGURG || signum == SIGWINCH)
    {
        // ignore
        return 0;
    }

    myst_thread_t* thread = myst_thread_self();
    myst_process_t* process = myst_process_self();
    myst_thread_t* process_thread = process->main_process_thread;

    // If the main thread has not been sent signal or has not exited already
    // forward this exception to the main thread to cause the whole process to
    // exit with this signal
    if ((thread != process_thread) &&
        //(signum != SIGKILL))
        ((signum == SIGABRT) || (signum == SIGSEGV)))
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

        process->exit_status = 128 + signum;
        thread->thread_status = MYST_KILLED;
        process->terminating_signum = signum;

        /* If we were forked and fork mode is wait for exec, notify calling
         * parent
         */
        if (process->is_pseudo_fork_process)
        {
            myst_fork_exec_futex_wake(process);
        }
    }

    myst_longjmp(&thread->jmpbuf, 1);

    // Unreachable
    assert(0);
    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static long _handle_one_signal(
    unsigned signum,
    siginfo_t* siginfo,
    mcontext_t* mcontext)
{
    long ret = 0;
    ucontext_t context;

#if TRACE
    printf("%s(%u %s)\n", __FUNCTION__, signum, myst_signum_to_string(signum));
#endif

    // Caution: This function should not allocate memory since the signal
    // handler may not return due to a long jump.

    ECHECK(_check_signum(signum));

    // Use a zeroed ucontext_t unless the caller passed in a mconext
    // (register states). Note we modified pthread_cancel in MUSL to
    // avoid the dependency on mcontext.
    memset(&context, 0, sizeof(context));

    if (mcontext != NULL)
        context.uc_mcontext = *mcontext;

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
        ret = _default_signal_handler(signum);
    }
    else if (action->handler == (uint64_t)SIG_IGN)
    {
        ret = 0;
    }
    else
    {
        bool use_alt_stack = false;
        struct _handler_wrapper_arg arg = {0};
        uint64_t orig_mask = thread->signal.mask;

        // add mask specified in action->sa_mask
        thread->signal.mask |= action->mask;
        if ((action->flags & SA_NODEFER) == 0)
            thread->signal.mask |= mask;

        // ATTN: handle other signal flags, e.g., SA_NOCLDSTOP, SA_NOCLDWAIT,
        // SA_RESETHAND, SA_RESTART, etc.

        /* save the original fsbase */
        void* original_fsbase = myst_get_fsbase();
        stack_t* altstack = &thread->signal.altstack;

        /* restore the user-space fsbase, which is pthread_self() */
        myst_set_fsbase(thread->crt_td);

        use_alt_stack = (action->flags & SA_ONSTACK) &&
                        !(altstack->ss_flags & (SS_DISABLE | SS_ONSTACK)) &&
                        (altstack->ss_sp != 0);

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
            // Remember this thread is already on the alt stack. We check
            // this flag when the next signal comes in, if true we will
            // continue on the current (alt) stack instead of starting
            // from the top of the alt stack.
            altstack->ss_flags |= SS_ONSTACK;

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

            altstack->ss_flags &= ~SS_ONSTACK; // Done with the alt stack.
        }
        else
            _handler_wrapper(&arg);

        // Copy back mcontext (register states)
        if ((action->flags & SA_SIGINFO) && mcontext != NULL)
            *mcontext = context.uc_mcontext;

        /* restore the original fsbase */
        myst_set_fsbase(original_fsbase);

        thread->signal.mask = orig_mask; /* Restore to original mask */
    }

done:

    return ret;
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="

int myst_signal_has_active_signals(myst_thread_t* thread)
{
    uint64_t unblocked = MYST_SIG_UNBLOCKED(thread->signal.mask);
    uint64_t active_signals = thread->signal.pending & unblocked;
    return active_signals != 0;
}

long myst_signal_process(myst_thread_t* thread)
{
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
#pragma GCC diagnostic pop

long myst_signal_deliver(
    myst_thread_t* thread,
    unsigned signum,
    siginfo_t* siginfo)
{
    long ret = 0;
    struct siginfo_list_item* new_item = NULL;

    ECHECK(_check_signum(signum));

    uint64_t mask = (uint64_t)1 << (signum - 1);

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

        // Wake up target if necessary
        if (thread->signal.waiting_on_event)
        {
            myst_tcall_wake(thread->event);
        }
    }

    /* Make sure any polls get woken up to process any outstanding events */
    myst_tcall_poll_wake();

    if (!__sync_val_compare_and_swap(&thread->pause_futex, 0, 1))
    {
        ret = myst_futex_wake(&thread->pause_futex, 1);
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

done:
    if (ret != 0)
    {
        free(child_thread->process->signal.sigactions);
        child_thread->process->signal.sigactions = NULL;
    }
    return ret;
}

long myst_handle_host_signal(siginfo_t* siginfo, mcontext_t* mcontext)
{
    return _handle_one_signal(siginfo->si_signo, siginfo, mcontext);
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
    }

    if (ss != NULL)
    {
        // We don't support swapcontext in libc. No point
        // to support SS_AUTODISARM which was introduced to enable it.
        // The only flag allowed here is SS_DISABLE.
        if (ss->ss_flags & ~(SS_DISABLE) != 0)
            ERAISE(-EINVAL);

        if (me->signal.altstack.ss_flags & SS_ONSTACK)
            ERAISE(-EPERM);

        if (ss->ss_flags & SS_DISABLE)
        {
            me->signal.altstack.ss_flags |= SS_DISABLE;
            me->signal.altstack.ss_sp = NULL;
            me->signal.altstack.ss_size = 0;
        }
        else
        {
            if (ss->ss_size < MINSIGSTKSZ)
                ERAISE(-ENOMEM);
            me->signal.altstack = *ss;
        }
    }

done:
    return ret;
}