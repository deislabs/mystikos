#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/fsgs.h>
#include <myst/printf.h>
#include <myst/signal.h>

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
    assert(thread && myst_is_process_thread(thread));
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

// No/default signal disposition specified, use the default action. See
// https://man7.org/linux/man-pages/man7/signal.7.html for details.
static long _default_signal_handler(unsigned signum)
{
    if (signum == SIGCHLD || signum == SIGCONT || signum == SIGURG ||
        signum == SIGWINCH)
    {
        // ignore
        return 0;
    }

    myst_thread_t* thread = myst_thread_self();

    // A hard kill. Never returns.
    thread->exit_status = -1;
    thread->status = MYST_KILLED;
    myst_longjmp(&thread->jmpbuf, 1);

    // Unreachable
    assert(0);
    return 0;
}

static long _handle_one_signal(unsigned signum, siginfo_t* siginfo)
{
    long ret = 0;
    ECHECK(_check_signum(signum));
    struct vars
    {
        ucontext_t context;
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    memset(&v->context, 0, sizeof(v->context));

    myst_thread_t* thread = myst_thread_self();

    uint64_t mask = (uint64_t)1 << (signum - 1);

    // Both the child and process thread should point to array of sigactions.
    assert(thread->signal.sigactions != NULL);

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
            // Use a zeroed ucontext_t. Only usage in libc seems to be
            // pthread_cancel, which we modified to avoid the dependency.
            ((sigaction_function_t)(action->handler))(
                signum, siginfo, &v->context);
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

    if (v)
        free(v);

    return ret;
}

long myst_signal_process(myst_thread_t* thread)
{
    while (thread->signal.pending != 0)
    {
        unsigned bitnum = __builtin_ctzl(thread->signal.pending);

        // Create a local copy and free the global one.
        siginfo_t local_siginfo = {0};
        siginfo_t* siginfo = NULL;
        if (thread->signal.siginfos[bitnum])
        {
            local_siginfo = *thread->signal.siginfos[bitnum];
            free(thread->signal.siginfos[bitnum]);
            thread->signal.siginfos[bitnum] = NULL;
            siginfo = &local_siginfo;
        }

        // Clear the pending bit. We are ready for the next signal.
        thread->signal.pending &= ~((uint64_t)1 << bitnum);

        // Signal numbers are 1 based.
        unsigned signum = bitnum + 1;
        _handle_one_signal(signum, siginfo);
    }
    return 0;
}

long myst_signal_deliver(
    myst_thread_t* thread,
    unsigned signum,
    siginfo_t* siginfo)
{
    long ret = 0;
    ECHECK(_check_signum(signum));

    uint64_t mask = (uint64_t)1 << (signum - 1);

    if (!(thread->signal.mask & mask) || signum == SIGKILL || signum == SIGSTOP)
    {
        // Multiple threads could be trying to deliver a signal
        // to this thread simultaneously. Protect with a lock.
        myst_spin_lock(&thread->signal.lock);

        // If the signal is not blocked, wait for the same signal from a
        // previous delivery to be handled.
        while (thread->signal.pending & mask)
            ;
        thread->signal.siginfos[signum - 1] = siginfo;
        thread->signal.pending |= mask;

        myst_spin_unlock(&thread->signal.lock);
    }
    else
    {
        free(siginfo); // Free the siginfo object if not delivered.
    }

done:
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
    return ret;
}
