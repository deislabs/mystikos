#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/fsgs.h>
#include <myst/printf.h>
#include <myst/signal.h>

#define MYST_SIG_UNBLOCKED(mask) \
    (~mask) | ((uint64_t)1 << (SIGKILL - 1)) | ((uint64_t)1 << (SIGSTOP - 1));

/* The lock for installing signal dispositions */
static myst_spinlock_t _lock = MYST_SPINLOCK_INITIALIZER;

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

int myst_signal_init(myst_thread_t* thread)
{
    int ret = 0;

    thread->signal.sigactions = calloc(NSIG, sizeof(posix_sigaction_t));

    if (thread->signal.sigactions == NULL)
        ERAISE(-ENOMEM);

done:
    return ret;
}

void myst_signal_free(myst_thread_t* thread)
{
    sigset_t block_all;

    assert(thread && myst_is_process_thread(thread));

    // Block all signals from this point. Not that there are a couple of
    // none-blocking signals, but that delivery scenario will ignore it because
    // sigactions is NULL
    memset(&block_all, -1, sizeof(block_all));
    myst_signal_sigprocmask(SIG_BLOCK, &block_all, NULL);

    free(thread->signal.sigactions);
    thread->signal.sigactions = NULL;
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

    myst_thread_t* thread = myst_thread_self();
    assert(thread->signal.sigactions);

    // Sigactions are shared process-wide. We need to ensure
    // no simultaneous updates from multiple threads.
    myst_spin_lock(&_lock);

    if (old_action)
        *old_action = thread->signal.sigactions[signum - 1];

    if (new_action)
        thread->signal.sigactions[signum - 1] = *new_action;

    myst_spin_unlock(&_lock);

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

// No/default signal disposition specified, use the default action. See
// https://man7.org/linux/man-pages/man7/signal.7.html for details.
static long _default_signal_handler(unsigned signum)
{
    if (signum == SIGCHLD || signum == SIGCONT || signum == SIGSTOP ||
        signum == SIGURG || signum == SIGWINCH)
    {
        // ignore
        return 0;
    }

    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* process_thread = myst_find_process_thread(thread);

    // A hard kill. Never returns.
    // For SIGABRT, throw it to the process thread.
    if (signum == SIGABRT)
    {
        myst_signal_deliver(process_thread, signum, NULL);
        if (process_thread->signal.waiting_on_event)
        {
            myst_tcall_wake(process_thread->event);
        }
    }

    /* If we were forked and fork mode is wait for exec, notify calling parent
     */
    if (process_thread->clone.flags & CLONE_VFORK)
    {
        myst_fork_exec_futex_wake(process_thread);
    }

    thread->exit_status = 128 + signum;
    thread->status = MYST_KILLED;
    thread->terminating_signum = signum;
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

    uint64_t mask = (uint64_t)1 << (signum - 1);

    // Both the child and process thread should point to array of sigactions.
    // The only exception to this is during shutdown. All signals that can be
    // blocked have been, but the non-blocking signals may still get through so
    // we ignore then
    if (thread->signal.sigactions == NULL)
    {
        return 0;
    }

    posix_sigaction_t* action = &thread->signal.sigactions[signum - 1];
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
        uint64_t orig_mask = thread->signal.mask;

        // add mask specified in action->sa_mask
        thread->signal.mask |= action->mask;
        if ((action->flags & SA_NODEFER) == 0)
            thread->signal.mask |= mask;

        // ATTN: handle other signal flags, e.g., SA_NOCLDSTOP, SA_NOCLDWAIT,
        // SA_ONSTACK, SA_RESETHAND, SA_RESTART, etc.

        /* save the original fsbase */
        void* original_fsbase = myst_get_fsbase();

        /* restore the user-space fsbase, which is pthread_self() */
        myst_set_fsbase(thread->crt_td);

        if ((action->flags & SA_SIGINFO) != 0)
        {
            ((sigaction_function_t)(action->handler))(
                signum, siginfo, &context);
            // Copy back mcontext (register states)
            if (mcontext != NULL)
                *mcontext = context.uc_mcontext;
        }
        else
        {
            ((sigaction_handler_t)(action->handler))(signum);
        }

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

    myst_thread_t* process = myst_find_process_thread(thread);

    assert(process);

    // Union the pending signals targeted for the thread and process.
    _uint64_to_sigset(thread->signal.pending | process->signal.pending, set);

    return 0;
}

long myst_signal_clone(myst_thread_t* parent, myst_thread_t* child)
{
    int ret = 0;
    ECHECK(myst_signal_init(child));

    // Clone the signal dispositions
    unsigned len = (NSIG - 1) * sizeof(posix_sigaction_t);
    memcpy(child->signal.sigactions, parent->signal.sigactions, len);

    // Clone the signal mask
    child->signal.mask = parent->signal.mask;

done:
    if (ret != 0)
    {
        free(child->signal.sigactions);
        child->signal.sigactions = NULL;
    }
    return ret;
}

long myst_handle_host_signal(siginfo_t* siginfo, mcontext_t* mcontext)
{
    return _handle_one_signal(siginfo->si_signo, siginfo, mcontext);
}
