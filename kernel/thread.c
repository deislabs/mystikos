// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <myst/assume.h>
#include <myst/atexit.h>
#include <myst/atomic.h>
#include <myst/cond.h>
#include <myst/config.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/file.h>
#include <myst/fsgs.h>
#include <myst/futex.h>
#include <myst/hex.h>
#include <myst/kernel.h>
#include <myst/lfence.h>
#include <myst/mmanutils.h>
#include <myst/options.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/procfs.h>
#include <myst/setjmp.h>
#include <myst/sharedmem.h>
#include <myst/signal.h>
#include <myst/spinlock.h>
#include <myst/stack.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/time.h>
#include <myst/times.h>
#include <myst/trace.h>

//#define TRACE

myst_spinlock_t myst_process_list_lock = MYST_SPINLOCK_INITIALIZER;

/* The total number of threads running (including the main thread) */
static _Atomic(size_t) _num_threads = 1;

/* Main top-level process. This process is the last process object to be
 * deleved. */
myst_process_t* myst_main_process = 0;

/*
**==============================================================================
**
** TID generation
**
**     Generate thread ids rather than depending on the ones provided by the
**     target.
**
**==============================================================================
*/

#define MIN_TID 100

pid_t myst_generate_tid(void)
{
    static pid_t _tid = MIN_TID;
    static myst_spinlock_t _lock = MYST_SPINLOCK_INITIALIZER;
    pid_t tid;

    myst_spin_lock(&_lock);
    {
        if (_tid < MIN_TID)
            _tid = MIN_TID;

        tid = _tid++;
    }
    myst_spin_unlock(&_lock);

    return tid;
}

/*
**==============================================================================
**
** Entry stack
**
**    Allocate the temporary stack uesd by thread initialization
**
**==============================================================================
*/

#define ENTRY_STACK_ALIGNMENT 16
#define PROCESS_ENTRY_STACK_SIZE 65536
#define THREAD_ENTRY_STACK_SIZE 8192

static long _get_entry_stack(myst_thread_t* thread)
{
    long ret = 0;
    size_t stack_size;

    if (myst_is_process_thread(thread))
        stack_size = PROCESS_ENTRY_STACK_SIZE;
    else
        stack_size = THREAD_ENTRY_STACK_SIZE;

    /* allocate a new stack since the OE caller stack is very small */
    if (!(thread->entry_stack = memalign(ENTRY_STACK_ALIGNMENT, stack_size)))
        ERAISE(-ENOMEM);
    thread->entry_stack_size = stack_size;

    ECHECK(myst_register_stack(thread->entry_stack, thread->entry_stack_size));

done:
    if (ret < 0)
    {
        free(thread->entry_stack);
        thread->entry_stack = NULL;
        thread->entry_stack_size = 0;
    }

    return ret;
}

/*
**==============================================================================
**
** cookie map:
**
**     This structure maps cookies to threads. When a thread is created, the
**     kernel passes a cookie to the target (myst_tcall_create_thread).
**     The host creates a new thread and then calls back into the kernel on
**     that thread (myst_run_thread). Rather than passing a thread pointer
**     directly to the target, we pass a cookie instead. A mapping only exists
**     while a new thread is being created and deleted from the map immediately
**     after the thread enters the kernel. The map provides functions for
**     adding and removing a mapping.
**
**     A cookie is a 64-bit integer whose upper 32-bits are an index into the
**     cookie map array, and the lower 32-bits are a random integer.
**
**     The cookie map provides two operations:
**         _get_cookie() -- assigns and returns a cookie for the new pointer.
**         _put_cookie() -- deletes a cookie and returns the thread pointer.
**
**     Both operations are O(1)
**
**==============================================================================
*/

#define MAX_COOKIE_MAP_ENTRIES (1024 + 256)

typedef struct cookie_map_entry
{
    uint64_t cookie;
    myst_thread_t* thread;
    size_t next1; /* one-based next pointer */
} cookie_map_entry_t;

static cookie_map_entry_t _cookie_map[MAX_COOKIE_MAP_ENTRIES];
static size_t _cookie_map_next;  /* next available entry */
static size_t _cookie_map_free1; /* free list of cookie entries (one-based) */
static myst_spinlock_t _cookie_map_lock;

/* assign a cookie for the given thread pointer and return the cookie */
static uint64_t _get_cookie(myst_thread_t* thread)
{
    uint32_t rand;
    uint64_t cookie;

    /* generate a random number (any value is fine except zero) */
    do
    {
        if (myst_syscall_getrandom(&rand, sizeof(rand), 0) != sizeof(rand))
            myst_panic("getrandom failed");
    } while (rand == 0);

    /* add a new entry to the cookie map */
    myst_spin_lock(&_cookie_map_lock);
    {
        uint32_t index;

        if (_cookie_map_next < MAX_COOKIE_MAP_ENTRIES)
        {
            index = (uint32_t)_cookie_map_next++;
        }
        else if (_cookie_map_free1 != 0)
        {
            /* take first entry on the free list (adjust to zero-based) */
            index = (uint32_t)(_cookie_map_free1 - 1);

            /* remove this entry from the free list */
            _cookie_map_free1 = _cookie_map[index].next1;
        }
        else
        {
            myst_panic("cookie map exhausted");
        }

        cookie = ((uint64_t)index << 32) | (uint64_t)rand;

        _cookie_map[index].cookie = cookie;
        _cookie_map[index].thread = thread;
        _cookie_map[index].next1 = 0;
    }
    myst_spin_unlock(&_cookie_map_lock);

    return cookie;
}

/* fetch the cookie form the cookie map, while deleting the entry */
static myst_thread_t* _put_cookie(uint64_t cookie)
{
    uint32_t index;
    myst_thread_t* thread = NULL;

    if (cookie == 0)
        myst_panic("zero-valued cookie");

    myst_lfence();

    /* extract the index from the cookie */
    index = (uint32_t)((cookie & 0xffffffff00000000) >> 32);

    myst_spin_lock(&_cookie_map_lock);
    {
        if (index >= _cookie_map_next)
            myst_panic("bad cookie index");

        if (_cookie_map[index].cookie != cookie)
            myst_panic("cookie mismatch");

        thread = _cookie_map[index].thread;

        /* clear the entry */
        _cookie_map[index].cookie = 0;
        _cookie_map[index].thread = NULL;

        /* add the entry to the free list */
        _cookie_map[index].next1 = _cookie_map_free1;
        _cookie_map_free1 = index + 1;
    }
    myst_spin_unlock(&_cookie_map_lock);

    return thread;
}

/*
**==============================================================================
**
** zombie list implementation:
**
**     processes are moved onto the zombie list after exiting.
**     They are removed from the active process linked list.
**     Lock list with myst_process_list_lock.
**
**==============================================================================
*/

static myst_process_t* _zombies_head;

static void _free_zombies(void* arg)
{
    (void)arg;

    for (myst_process_t* p = _zombies_head; p;)
    {
        myst_process_t* next = p->zombie_next;

        memset(p, 0xdd, sizeof(myst_process_t));
        free(p);

        p = next;
    }

    _zombies_head = NULL;
}

void send_sigchld_to_parent(myst_process_t* process)
{
    // Find process thread from pid
    myst_process_t* parent = myst_find_process_from_pid(process->ppid, false);

    if (parent == NULL) // should not happen
        return;

    siginfo_t* siginfo;

    if (!(siginfo = calloc(1, sizeof(siginfo_t))))
        return;

    siginfo->si_code = SI_USER;
    siginfo->si_signo = SIGCHLD;
    siginfo->si_pid = process->pid;
    siginfo->si_uid = process->main_process_thread->euid;

    myst_signal_deliver(parent->main_process_thread, SIGCHLD, siginfo);
}

void myst_zombify_process(myst_process_t* process)
{
    static bool _initialized;

    if (!_initialized)
    {
        myst_atexit(_free_zombies, NULL);
        _initialized = true;
    }

    process->zombie_next = _zombies_head;
    process->zombie_prev = NULL;

    if (_zombies_head)
    {
        _zombies_head->zombie_prev = process;
        _zombies_head = process;
    }
    else
    {
        _zombies_head = process;
    }

    process->main_process_thread = NULL;

    // remove from process list
    if (process->prev_process)
        process->prev_process->next_process = process->next_process;
    if (process->next_process)
        process->next_process->prev_process = process->prev_process;
    process->prev_process = NULL;
    process->next_process = NULL;
}

/* Send SIGCHLD to parent and zombify process atomically. This way wait() calls
 * from parent are ensured to be serialized. */
void myst_send_sigchld_and_zombify_process(myst_process_t* process)
{
    pid_t vfork_parent_pid = process->vfork_parent_pid;
    pid_t vfork_parent_tid = process->vfork_parent_tid;
    bool is_pseudo_fork_process = process->is_pseudo_fork_process;
    process->is_pseudo_fork_process = false;
    process->vfork_parent_tid = 0;
    process->vfork_parent_pid = 0;

    myst_spin_lock(&myst_process_list_lock);
    {
        send_sigchld_to_parent(process);
        myst_zombify_process(process);
    }
    myst_spin_unlock(&myst_process_list_lock);

    /* If this process was created as part of a fork() and the parent is
     * running in wait-exec mode, signal that thread for wakeup */
    if (is_pseudo_fork_process && vfork_parent_pid)
    {
        myst_fork_exec_futex_wake(vfork_parent_pid, vfork_parent_tid);
    }
}

static bool _wait_matcher(
    MYST_UNUSED const char* type,
    pid_t pid,
    myst_process_t* our_process,
    myst_process_t* check_process)
{
    bool match = false;
    if (pid > 0) /* wait for a specific child process */
    {
        match = (check_process->pid == pid);
#ifdef TRACE
        printf(
            "matcher(%s): Wait for specific pid %u, found pid=%u, ppid=%u, "
            "pgid=%u: %s\n",
            type,
            pid,
            check_process->pid,
            check_process->ppid,
            check_process->pgid,
            match ? "true" : "false");
#endif
    }
    else if ((pid == -1)) /* wait for any child process */
    {
        match = (check_process->ppid == our_process->pid);
#ifdef TRACE
        printf(
            "matcher(%s): Wait for children of our pid %u: found pid=%u, "
            "ppid=%u, pgid=%u: "
            "%s\n",
            type,
            our_process->pid,
            check_process->pid,
            check_process->ppid,
            check_process->pgid,
            match ? "true" : "false");
#endif
    }
    else if (pid == 0) /* wait for any process in our process group */
    {
        match =
            ((check_process->ppid == our_process->pid) &&
             (check_process->pgid == our_process->pgid));
#ifdef TRACE
        printf(
            "matcher(%s): Wait for any process with our pgid %u: found pid=%u, "
            "ppid=%u, pgid=%u: "
            "%s\n",
            type,
            our_process->pgid,
            check_process->pid,
            check_process->ppid,
            check_process->pgid,
            match ? "true" : "false");
#endif
    }
    else if (pid < -1) /* specific process group */
    {
        match =
            ((check_process->ppid == our_process->pid) &&
             ((-pid) == check_process->pgid));
#ifdef TRACE
        printf(
            "matcher(%s): Wait for specific pgid %u: found pid=%u, ppid=%u, "
            "pgid=%u: %s\n",
            type,
            -pid,
            check_process->pid,
            check_process->ppid,
            check_process->pgid,
            match ? "true" : "false");
#endif
    }
    return match;
}

long myst_syscall_wait4(
    pid_t pid,
    int* wstatus,
    int options,
    struct rusage* rusage)
{
    long ret = 0;

    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED))
        ERAISE(-EINVAL);

#ifdef TRACE
    printf(
        "***wait4 from process %u, wait for pid %d, WNOHANG=%s, WUNTRACED=%s\n",
        myst_process_self()->pid,
        pid,
        ((options & WNOHANG) == WNOHANG) ? "true" : "false",
        ((options & WUNTRACED) == WUNTRACED) ? "true" : "false");
#endif

    ECHECK(ret = myst_wait(pid, wstatus, NULL, options, rusage));

done:
    return ret;
}

long myst_syscall_waitid(
    idtype_t idtype,
    id_t id,
    siginfo_t* infop,
    int options)
{
    long ret = 0;

    if (options & ~(WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT))
        ERAISE(-EINVAL);

#ifdef TRACE
    printf(
        "***waitid from process %u, idtype %d, id %d,WNOHANG=%s)\n",
        myst_process_self()->pid,
        idtype,
        id,
        ((options & WNOHANG) == WNOHANG) ? "NO HANG" : "HANG");
#endif

    // Convert waitid args to waitpid/wait4 args
    int pid = 0;
    if (idtype == P_PID)
    {
        pid = id;
    }
    else if (idtype == P_PGID)
    {
        pid = -id;
    }
    else if (idtype == P_ALL)
    {
        pid = -1;
    }
    else
    {
        ERAISE(-EINVAL);
    }

    ECHECK(myst_wait(pid, NULL, infop, options, NULL));

    if (ret != 1)
        ret = 0;

done:
    return ret;
}

/* not making static or compile out without trace so it can be used by the
 * debugger to dump the status */
void _myst_dump_wstatus(int wstatus, const char* process_type)
{
    printf("*** WSTATUS DETAILS FOR %s PROCESS: %d\n", process_type, wstatus);
    printf(
        "    WIFEXITED (exited through exit(), _exit() or "
        "return from main): %s\n",
        WIFEXITED(wstatus) ? "true" : "false");
    printf(
        "    WEXITSTATUS (return code via exit(), _exit() or "
        "return from main): %u\n",
        WEXITSTATUS(wstatus));
    printf(
        "    WIFSIGNALED (exited via signal): %s\n",
        WIFSIGNALED(wstatus) ? "true" : "false");
    printf("    WTERMSIG (signal code to terminate): %u\n", WTERMSIG(wstatus));
    printf(
        "    WCOREDUMP (signaled and dumped core, not "
        "supported): %s\n",
        WCOREDUMP(wstatus) ? "true" : "false");
    printf(
        "    WIFSTOPPED (signaled to stop): "
        "%s\n",
        WIFSTOPPED(wstatus) ? "true" : "false");
    if (WIFSTOPPED(wstatus))
        printf(
            "    WSTOPSIG (signal code to stop, not "
            "supported): "
            "%u\n",
            WSTOPSIG(wstatus));
    printf(
        "    WIFCONTINUED (signaled to resumed after stop, not "
        "supported): %s\n",
        WIFCONTINUED(wstatus) ? "true" : "false");
}

long myst_wait(
    pid_t pid,
    int* wstatus,
    siginfo_t* infop,
    int options,
    struct rusage* rusage)
{
    long ret = -1;
    bool locked = false;
    myst_process_t* process = myst_process_self();
    myst_process_t* p;

    if (rusage)
        memset(rusage, 0, sizeof(*rusage));

    /* If this is the only process then raise ECHILD */
    if (process->next_process == NULL && process->prev_process == NULL &&
        _zombies_head == NULL)
    {
        ERAISE(-ECHILD);
    }

    myst_spin_lock(&myst_process_list_lock);
    locked = true;

    for (;;)
    {
        /* search the zombie list for a process thread */
        for (p = _zombies_head; p; p = p->zombie_next)
        {
            if (_wait_matcher("zombie", pid, process, p))
            {
                if (wstatus)
                {
                    *wstatus = 0;

                    if (p->terminating_signum)
                    {
                        *wstatus = (p->terminating_signum & 0x7f);
#ifdef WCOREDUMP
                        if (p->terminating_signum == SIGQUIT ||
                            p->terminating_signum == SIGILL ||
                            p->terminating_signum == SIGTRAP ||
                            p->terminating_signum == SIGABRT ||
                            p->terminating_signum == SIGFPE ||
                            p->terminating_signum == SIGSEGV ||
                            p->terminating_signum == SIGBUS ||
                            p->terminating_signum == SIGXFSZ ||
                            p->terminating_signum == SIGXCPU)
                        {
                            *wstatus |= 0x80;
                        }
#endif
                    }
                    else
                    {
                        *wstatus = ((p->exit_status & 0xff) << 8);
                    }
#ifdef TRACE
                    _myst_dump_wstatus(*wstatus, "ZOMBIE");
#endif
                }
                if (infop)
                {
                    infop->si_pid = p->pid;
                    infop->si_uid = p->process_uid;
                    infop->si_signo = SIGCHLD;

                    if (p->terminating_signum)
                    {
                        infop->si_code = CLD_KILLED;
                        infop->si_status = p->terminating_signum;
                    }
                    else
                    {
                        infop->si_code = CLD_EXITED;
                        infop->si_status = p->exit_status;
                    }
                }
                ret = p->pid;

                if (!(options & WNOWAIT))
                {
                    // remove from zombie list
                    if (p->zombie_prev == NULL)
                    {
                        _zombies_head = p->zombie_next;
                    }
                    else
                    {
                        p->zombie_prev->zombie_next = p->zombie_next;
                    }
                    if (p->zombie_next != NULL)
                        p->zombie_next->zombie_prev = p->zombie_prev;

                    /* inherit the child process times into the parent */
                    myst_times_add_child_times_to_parent_times(process, p);

                    // free zombie process
                    free(p);
                }

                goto done;
            }
        }

        if (options & WUNTRACED)
        {
            /* If we have a match and it is sleeping we can return */
            p = process->prev_process;
            while (p && !_wait_matcher("stopped", pid, process, p) &&
                   (p->sigstop_futex == 0))
            {
                p = p->prev_process;
            }
            if (p == NULL)
            {
                // now processes right
                p = process->next_process;
                while (p && !_wait_matcher("stopped", pid, process, p) &&
                       (p->sigstop_futex == 0))
                {
                    p = p->next_process;
                }
            }
            if (p != NULL && p->sigstop_futex == 1)
            {
                if (wstatus)
                {
                    *wstatus = (SIGSTOP << 8) + 0x7F;

#ifdef TRACE
                    _myst_dump_wstatus(*wstatus, "STOPPED");
#endif
                }
                if (infop)
                {
                    infop->si_pid = p->pid;
                    infop->si_uid = p->process_uid;
                    infop->si_signo = SIGSTOP;
                    infop->si_code = CLD_STOPPED;
                    infop->si_status = 0;
                }
                ret = p->pid;

                goto done;
            }
        }

        /* no zombies found, but are there any running childred? If not then
         * ECHILD returned */

        // first processes left
        p = process->prev_process;
        while (p && !_wait_matcher("active", pid, process, p))
        {
            p = p->prev_process;
        }
        if (p == NULL)
        {
            // now processes right
            p = process->next_process;
            while (p && !_wait_matcher("active", pid, process, p))
            {
                p = p->next_process;
            }
        }
        if (p == NULL)
        {
#ifdef TRACE
            printf("Returning ECHILD\n");
#endif
            ERAISE(-ECHILD);
        }

        if ((options & WNOHANG))
        {
            ret = 0;
            goto done;
        }

#ifdef TRACE
        if (pid == 0)
        {
            printf(
                "Waiting for new zombification of child with our pgid=%u of "
                "our process %u\n",
                process->pgid,
                process->pid);
        }
        else if (pid > 0)
        {
            printf(
                "Waiting for new zombification of child whose pid=%d from our "
                "process %u\n",
                pid,
                process->pid);
        }
        else if (pid == -1)
        {
            printf(
                "Waiting for new zombification of any child of our process "
                "%u\n",
                process->pid);
        }
        else /* < -1 */
        {
            printf(
                "Waiting for new zombification of child whose pgid=%d from our "
                "process %u\n",
                -pid,
                process->pid);
        }
#endif
        myst_spin_unlock(&myst_process_list_lock);
        locked = false;
        myst_sleep_msec(100, true);
        myst_spin_lock(&myst_process_list_lock);
        locked = true;

        // current implementation does not cause all waiters to wake up
        // myst_cond_wait(&_zombies_cond, &myst_process_list_lock);
    }

done:

    if (locked)
        myst_spin_unlock(&myst_process_list_lock);

#ifdef TRACE
    printf("myst_waitpid() returning %ld\n", ret);
#endif
    return ret;
}

myst_thread_t* myst_find_thread(int tid)
{
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* target = NULL;
    myst_thread_t* t = NULL;

    myst_spin_lock(thread->thread_lock);

    // Search forward in the doubly linked list for a match
    for (t = thread; t != NULL; t = t->group_next)
    {
        if (t->tid == tid)
        {
            target = t;
            break;
        }
    }

    if (target == NULL)
    {
        // Search backward in the doubly linked list for a match
        for (t = thread->group_prev; t != NULL; t = t->group_prev)
        {
            if (t->tid == tid)
            {
                target = t;
                break;
            }
        }
    }

    myst_spin_unlock(thread->thread_lock);
    return target;
}

// Caller should hold myst_proces_list_lock!
myst_process_t* myst_find_process_from_pid(pid_t pid, bool include_zombies)
{
    myst_process_t* p = NULL;

    // Search forward in the doubly linked list for a match
    p = myst_main_process;
    while (p && p->pid != pid)
        p = p->next_process;

    if ((p == NULL) && include_zombies)
    {
        p = _zombies_head;
        while (p && p->pid != pid)
            p = p->zombie_next;
    }

    return p;
}

/* Find the thread that may be waiting for the fork-exec wait and wake it */
void myst_fork_exec_futex_wake(pid_t pid, pid_t tid)
{
    myst_process_t* waiter_process = NULL;
    myst_thread_t* waiter_thread = NULL;

    myst_spin_lock(&myst_process_list_lock);

    waiter_process = myst_find_process_from_pid(pid, false);

    if (waiter_process == NULL)
        goto done;

    /* find the waiter thread*/
    {
        myst_spin_lock(&waiter_process->thread_group_lock);
        waiter_thread = waiter_process->main_process_thread;

        while (waiter_thread && waiter_thread->tid != tid)
        {
            waiter_thread = waiter_thread->group_next;
        }

        if (waiter_thread)
        {
            __sync_val_compare_and_swap(
                &waiter_thread->fork_exec_futex_wait, 0, 1);
            myst_futex_wake(
                &waiter_thread->fork_exec_futex_wait,
                1,
                FUTEX_BITSET_MATCH_ANY);
        }

        myst_spin_unlock(&waiter_process->thread_group_lock);
    }

done:
    myst_spin_unlock(&myst_process_list_lock);
    return;
}

/*
**==============================================================================
**
** main thread implementation:
**
**==============================================================================
*/

bool myst_valid_td(const void* td)
{
    return td && ((const myst_td_t*)td)->self == td;
}

myst_thread_t* myst_thread_self(void)
{
    uint64_t value;
    myst_assume(myst_tcall_get_tsd(&value) == 0);

    myst_thread_t* thread = (myst_thread_t*)value;
    myst_assume(myst_valid_thread(thread));

    return thread;
}

myst_process_t* myst_process_self(void)
{
    return myst_thread_self()->process;
}

/* Force the caller stack to be aligned */
__attribute__((force_align_arg_pointer)) static long _call_thread_fn(void* arg)
{
    (void)arg;
    myst_thread_t* thread = myst_thread_self();
    thread->clone.fn(thread->clone.arg);
    return 0;
}

struct run_thread_arg
{
    myst_thread_t* thread;
    uint64_t cookie;
    uint64_t event;
    pid_t target_tid;
};

/* The target calls this from the new thread */
static long _run_thread(void* arg_)
{
    struct run_thread_arg* arg = arg_;
    myst_thread_t* thread = arg->thread;
    myst_process_t* process = thread->process;
    myst_td_t* target_td = myst_get_fsbase();
    myst_td_t* crt_td = NULL;
    bool is_child_thread;

    assert(myst_valid_td(target_td));

    if (__options.have_syscall_instruction)
        myst_set_gsbase(target_td);

    myst_assume(myst_valid_thread(thread));

    thread->target_tid = arg->target_tid;

    is_child_thread = thread->crt_td ? true : false;

    if (is_child_thread)
    {
        crt_td = thread->crt_td;
        myst_assume(myst_valid_td(crt_td));

        /* propagate the canary */
        crt_td->canary = target_td->canary;
    }

    /* set the target into the thread */
    thread->target_td = target_td;

    /* save the host thread event */
    myst_assume(arg->event != 0);
    thread->event = arg->event;

    /* bind this thread to the target thread-descriptor */
    myst_assume(myst_tcall_set_tsd((uint64_t)thread) == 0);

    /* bind thread to the C-runtime thread-descriptor */
    if (is_child_thread)
    {
        /* Set the TID for this thread (sets the tid field) */
        {
            myst_atomic_exchange(thread->clone.ptid, thread->tid);
            const int futex_op = FUTEX_WAKE | FUTEX_PRIVATE;
            myst_syscall_futex(thread->clone.ptid, futex_op, 1, 0, NULL, 0);
        }
    }

    /* Start time tracking for this thread */
    myst_times_start();

    /* Jump back here from exit */
    if (myst_setjmp(&thread->jmpbuf) != 0)
    {
        /* ---------- running C-runtime thread descriptor ---------- */

        assert(myst_gettid() != -1);

        /* restore the target thread descriptor */
        myst_set_fsbase(thread->target_td);

        /* ---------- running target thread descriptor ---------- */

        /* release the kernel stack that was set by SYS_exit */
        if (thread->exit_kstack)
        {
            myst_put_kstack(thread->exit_kstack);
            thread->exit_kstack = NULL;
        }

        // Release the kernel stack that were set by SYS_execve.
        if (thread->exec_kstack)
        {
            myst_put_kstack(thread->exec_kstack);
            thread->exec_kstack = NULL;
        }

        if (is_child_thread)
        {
            /* Wake up any thread waiting on ctid */
            myst_atomic_exchange(thread->clone.ctid, 0);
            const int futex_op = FUTEX_WAKE | FUTEX_PRIVATE;
            myst_syscall_futex(thread->clone.ctid, futex_op, 1, 0, NULL, 0);
        }

        /* Release memory objects owned by the main/process thread */
        if (!is_child_thread)
        {
            /* wait for all child threads to shutdown */
            {
                while (thread->group_next || thread->group_prev)
                {
                    myst_sleep_msec(10, false);
                }
            }

            myst_signal_free(process);

            /* Send SIGHUP to all our children */
            myst_send_sighup_child_processes(process);

            free(process->cwd);
            process->cwd = NULL;

            procfs_pid_cleanup(process->pid);

            /* Wait for any children to go away before proceeding */
            myst_wait_on_child_processes(process);

            /* unmap any mapping made by the process */
            myst_release_process_mappings(process->pid);

            if (process->exec_stack)
            {
                /* The stack is released as part of
                 * myst_release_process_mappings. Clear the pointer and size
                 * value */
                process->exec_stack = NULL;
                process->exec_stack_size = 0;
            }

#ifdef MYST_THREAD_KEEP_CRT_PTR
            if (process->exec_crt_data)
            {
                /* The crt data is released as part of
                 * myst_release_process_mappings. Clear the pointer and size
                 * value */
                process->exec_crt_data = NULL;
                process->exec_crt_size = 0;
            }
#endif

            /* clear the signal delivery altstack */
            myst_clear_signal_delivery_altstack(thread);

            /* unmapping closes fd's associated with mappings, so free fdtable
             * after all unmaps are done */
            if (process->fdtable)
            {
                myst_fdtable_free(process->fdtable);
                process->fdtable = NULL;
            }

            if (process->itimer)
                free(process->itimer);

            /* Only need to zombify the process thread.
            ATTN: referencing "process" after zombification is not safe,
            parent might have cleaned it up */
            myst_send_sigchld_and_zombify_process(process);
        }

        {
            myst_assume(_num_threads > 1);
            _num_threads--;
        }

        /* Free up the thread unmap-on-exit for child threads. */
        if (is_child_thread)
        {
            size_t i = thread->unmap_on_exit_used;
            while (i)
            {
                /* App process might have invoked SYS_mmap, which marks the
                 * memory as owned by the calling app process, and then
                 * SYS_myst_unmap_on_exit on the memory region. Clear the
                 * pid vector to make sure the unmapped memory is marked as
                 * not owned by any app process */
                myst_munmap_on_exit(
                    thread->unmap_on_exit[i - 1].ptr,
                    thread->unmap_on_exit[i - 1].size);
                i--;
            }
        }

        /* Only free child thread as parent is zombified so parent can wait on
         * this process */
        if (is_child_thread)
        {
            myst_spin_lock(&process->thread_group_lock);
            if (thread->group_prev)
                thread->group_prev->group_next = thread->group_next;
            if (thread->group_next)
                thread->group_next->group_prev = thread->group_prev;
            myst_spin_unlock(&process->thread_group_lock);
        }

        myst_signal_free_siginfos(thread);
        free(thread);

        /* Return to target, which will exit this thread */
    }
    else
    {
        /* ---------- running target thread descriptor ---------- */

        /* set the fsbase to C-runtime */
        if (is_child_thread)
            myst_set_fsbase(crt_td);

        /* ---------- running C-runtime thread descriptor ---------- */

        if (is_child_thread)
        {
            myst_call_on_stack(
                thread->clone.child_stack, _call_thread_fn, NULL);
            /* never returns */
            myst_panic("unexpected return");
        }
        else
        {
            // use the caller's stack since the one passed from posix_spawn
            // (in musl libc) is very small (1024 + PATH_MAX)
            _call_thread_fn(NULL);
        }

        /* unreachable */
    }

    return 0;
}

long myst_run_thread(uint64_t cookie, uint64_t event, pid_t target_tid)
{
    long ret = 0;
    myst_thread_t* thread;
    /* get the thread corresponding to this cookie */
    if (!(thread = _put_cookie(cookie)))
        ERAISE(-EINVAL);

    /* run the thread on the transient stack */
    struct run_thread_arg arg = {thread, cookie, event, target_tid};
    /* ATTN: We need to keep the entry stack for the myst_call_on_stack
     * to return properly. However, the thread object may be freed prior
     * to the return such that we can no longer obtain the reference
     * of the entry stack from it. As a workaround, we keep the reference
     * locally and release the entry stack before this function returns. */
    void* stack = thread->entry_stack;
    size_t stack_size = thread->entry_stack_size;
    uint64_t stack_end = (uint64_t)stack + stack_size;
    ECHECK(myst_call_on_stack((void*)stack_end, _run_thread, &arg));

    myst_unregister_stack(stack, stack_size);
    free(stack);

done:
    return ret;
}

static long _syscall_clone(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg,
    pid_t* ptid,
    void* newtls,
    pid_t* ctid)
{
    long ret = 0;
    uint64_t cookie = 0;
    myst_thread_t* current_thread = myst_thread_self();
    myst_process_t* current_process = myst_process_self();
    myst_thread_t* new_thread;

    if (!fn)
        ERAISE(-EINVAL);

    if (!myst_valid_td(newtls))
        ERAISE(-EINVAL);

    /* Check whether the maximum number of threads has been reached */
    {
        /* if too many threads already running */
        if (_num_threads == __myst_kernel_args.max_threads)
            ERAISE(-EAGAIN);

        _num_threads++;
    }

    /* Create and initialize the child thread struct */
    {
        if (!(new_thread = calloc(1, sizeof(myst_thread_t))))
            ERAISE(-ENOMEM);

        new_thread->magic = MYST_THREAD_MAGIC;
        new_thread->process = current_process;
        new_thread->crt_td = newtls;
        new_thread->run_thread = myst_run_thread;
        new_thread->thread_lock = &current_process->thread_group_lock;
        /* ATTN: we don't take a lock on _num_threads,
            thread names could be duplicates */
        snprintf(
            new_thread->name,
            sizeof(new_thread->name),
            "thread-%ld",
            _num_threads % 99999999);

        // Link up parent, child, and the previous head child of the parent,
        // if there is one, in the same thread group.

        myst_spin_lock(&current_process->thread_group_lock);
        new_thread->group_next = current_thread->group_next;
        new_thread->group_prev = current_thread;
        if (current_thread->group_next)
            current_thread->group_next->group_prev = new_thread;
        current_thread->group_next = new_thread;
        myst_spin_unlock(&current_process->thread_group_lock);

        /* save the clone() arguments */
        new_thread->clone.fn = fn;
        new_thread->clone.child_stack = child_stack;
        new_thread->clone.flags = flags;
        new_thread->clone.arg = arg;
        new_thread->clone.ptid = ptid;
        new_thread->clone.newtls = newtls;
        new_thread->clone.ctid = ctid;
        new_thread->pause_futex = 0;

        ECHECK(_get_entry_stack(new_thread));

        /* generate a thread id for this new thread and return on success*/
        new_thread->tid = myst_generate_tid();
        ret = new_thread->tid;
    }

    cookie = _get_cookie(new_thread);

    if (myst_tcall_create_thread(cookie) != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* create a new process (main) thread */
static long _syscall_clone_vfork(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg)
{
    long ret = 0;
    uint64_t cookie = 0;
    myst_thread_t* parent_thread = myst_thread_self();
    myst_process_t* parent_process = myst_process_self();
    myst_thread_t* child_thread = NULL;
    myst_process_t* child_process = NULL;
    bool added_to_process_list = false;

    if (!fn)
        ERAISE(-EINVAL);

    /* Check whether the maximum number of threads has been reached */
    {
        /* if too many threads already running */
        if (_num_threads == __myst_kernel_args.max_threads)
            ERAISE(-EAGAIN);

        _num_threads++;
    }

    /* Create and initialize the thread struct */
    {
        if (!(child_thread = calloc(1, sizeof(myst_thread_t))))
            ERAISE(-ENOMEM);
        if (!(child_process = calloc(1, sizeof(myst_process_t))))
            ERAISE(-ENOMEM);

        child_thread->process = child_process;
        child_process->main_process_thread = child_thread;

        child_thread->magic = MYST_THREAD_MAGIC;
        child_process->sid = parent_process->sid;
        child_process->ppid = parent_process->pid;
        child_process->pid = myst_generate_tid();
        child_thread->tid = child_process->pid;
        child_thread->run_thread = myst_run_thread;

        /* ATTN: we don't take a lock on _num_threads,
            thread names could be duplicates */
        snprintf(
            child_thread->name,
            sizeof(child_thread->name),
            "thread-%ld",
            _num_threads % 99999999);

        /* Inherit identity from parent process */
        child_thread->uid = parent_thread->uid;
        child_thread->euid = parent_thread->euid;
        child_thread->savuid = parent_thread->savgid;
        child_thread->fsuid = parent_thread->fsuid;
        child_thread->gid = parent_thread->gid;
        child_thread->egid = parent_thread->egid;
        child_thread->savgid = parent_thread->savgid;
        child_thread->fsgid = parent_thread->fsgid;
        memcpy(
            child_thread->supgid,
            parent_thread->supgid,
            parent_thread->num_supgid);
        memcpy(
            child_process->rlimits,
            parent_process->rlimits,
            sizeof(child_process->rlimits));
        child_thread->num_supgid = parent_thread->num_supgid;

        child_process->thread_group_lock = MYST_SPINLOCK_INITIALIZER;
        child_thread->thread_lock = &child_process->thread_group_lock;

        /* Inherit parent current working directory */
        child_process->cwd_lock = MYST_SPINLOCK_INITIALIZER;
        child_process->cwd = strdup(parent_process->cwd);
        if (child_process->cwd == NULL)
            ERAISE(-ENOMEM);

        /* inherit the umask from the parent process */
        child_process->umask = parent_process->umask;

        /* inherit process group ID */
        child_process->pgid = parent_process->pgid;

        if (myst_fdtable_clone(
                parent_process->fdtable, &child_process->fdtable) != 0)
            ERAISE(-ENOMEM);

        if (myst_signal_clone(parent_thread, child_thread) != 0)
            ERAISE(-ENOMEM);

        /* save the clone() arguments */
        child_thread->clone.fn = fn;
        child_thread->clone.child_stack = child_stack;
        child_thread->clone.flags = flags;
        child_thread->clone.arg = arg;

        /* If this is being called as part of a fork() call we may need to use
         * these to notify the parent processes tid to wake up in fork/exec mode
         */
        child_process->is_pseudo_fork_process = true;
        child_process->vfork_parent_pid = parent_process->pid;
        child_process->vfork_parent_tid = parent_thread->tid;

        /* Once we are a parent of a fork the shutdown of our process in the CRT
         * must change to not call any cleanup functions */
        parent_process->is_parent_of_pseudo_fork_process = true;

        /* Futexes for thread pausing and stopping processes, then resuming */
        child_process->sigstop_futex = 0;
        child_thread->pause_futex = 0;

        /* In case we are going to be used for fork-exec scenario where we need
         * to wait for exec or exit, reset the futex */
        parent_thread->fork_exec_futex_wait = 0;

        /* add this main process thread to the process linked list */
        myst_spin_lock(&myst_process_list_lock);
        child_process->next_process = parent_process->next_process;
        if (parent_process->next_process)
            parent_process->next_process->prev_process = child_process;
        child_process->prev_process = parent_process;
        parent_process->next_process = child_process;
        myst_spin_unlock(&myst_process_list_lock);
        added_to_process_list = true;

        /* Create /proc/[pid]/fd directory for new process thread */
        ECHECK(procfs_pid_setup(child_process->pid));

        /* Copy /proc/[parent-pid]/exe to child */
        {
            char* self_path = calloc(1, PATH_MAX);
            int tmp_ret =
                myst_syscall_readlink("/proc/self/exe", self_path, PATH_MAX);

            if (tmp_ret <= 0)
            {
                free(self_path);
                ERAISE(tmp_ret);
            }

            if ((tmp_ret =
                     procfs_setup_exe_link(self_path, child_process->pid)) != 0)
            {
                free(self_path);
                ERAISE(tmp_ret);
            }

            free(self_path);
        }

        /* Child inherits parent's posix shared memory objects */
        ECHECK(myst_posix_shm_share_mappings(child_process->pid));

        ECHECK(_get_entry_stack(child_thread));
    }

    cookie = _get_cookie(child_thread);

    if (myst_tcall_create_thread(cookie) != 0)
        ERAISE(-EINVAL);

    ret = child_process->pid;

    parent_process->num_pseudo_children++;

    child_process = NULL;
    child_thread = NULL;

done:
    if (child_process)
    {
        if (added_to_process_list)
        {
            myst_spin_lock(&myst_process_list_lock);
            if (child_process->prev_process)
                child_process->prev_process->next_process =
                    child_process->next_process;
            if (child_process->next_process)
                child_process->next_process->prev_process =
                    child_process->prev_process;
            myst_spin_unlock(&myst_process_list_lock);
        }
        if (child_process->cwd)
            free(child_process->cwd);
        if (child_process->fdtable)
            myst_fdtable_free(child_process->fdtable);
        free(child_process);
    }
    if (child_thread)
    {
        free(child_thread);
    }
    return ret;
}

long myst_syscall_clone(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg,
    pid_t* ptid,
    void* newtls,
    pid_t* ctid)
{
    if (flags & CLONE_VFORK)
        return _syscall_clone_vfork(fn, child_stack, flags, arg);
    else
        return _syscall_clone(fn, child_stack, flags, arg, ptid, newtls, ctid);
}

pid_t myst_gettid(void)
{
    if (__options.report_native_tids)
        return myst_thread_self()->target_tid;
    return myst_thread_self()->tid;
}

size_t myst_get_num_threads(void)
{
    return _num_threads;
}

bool myst_have_child_forked_processes(myst_process_t* process)
{
    pid_t pid = process->pid;
    myst_process_t* p;

    if (!process->is_parent_of_pseudo_fork_process)
        return false;

    myst_spin_lock(&myst_process_list_lock);
    p = process->next_process;

    while (p)
    {
        if ((p->ppid == pid) && (p->is_pseudo_fork_process))
        {
            break;
        }
        p = p->next_process;
    }
    myst_spin_unlock(&myst_process_list_lock);

    return p == NULL ? false : true;
}

long kill_child_fork_processes(myst_process_t* process)
{
    if (__myst_kernel_args.fork_mode == myst_fork_none)
        return 0;

    if (!process->is_parent_of_pseudo_fork_process)
        return false;

    myst_spin_lock(&myst_process_list_lock);
    myst_process_t* p = process->prev_process;
    pid_t pid = process->pid;

    /* Send signal to all children that are forks of us */
    while (p)
    {
        if ((p->ppid == pid) && (p->is_pseudo_fork_process))
            myst_signal_deliver(p->main_process_thread, SIGHUP, NULL);
        p = p->prev_process;
    }

    p = process->next_process;

    while (p)
    {
        if ((p->ppid == pid) && (p->is_pseudo_fork_process))
            myst_signal_deliver(p->main_process_thread, SIGHUP, NULL);
        p = p->next_process;
    }

    myst_spin_unlock(&myst_process_list_lock);

    return 0;
}

// Send kill signal to each thread in the group, and use the best effort to
// ensure they are stopped.
// Return: the number of still running child threads.
size_t myst_kill_thread_group()
{
    myst_thread_t* thread = myst_thread_self();
    myst_process_t* process = myst_process_self();
    myst_thread_t* t = NULL;
    size_t count = 0;

    myst_spin_lock(&process->thread_group_lock);

    // Send termination signal to all running child threads.
    for (t = process->main_process_thread; t != NULL; t = t->group_next)
    {
        if (t != thread)
        {
            count++;
            myst_signal_deliver(t, SIGKILL, 0);

            // Wake up the thread from futex_wait if necessary.
            if (t->signal.waiting_on_event)
            {
                myst_tcall_wake(t->event);
            }
        }
    }
    myst_spin_unlock(&process->thread_group_lock);

    // Wait for the child threads to exit.
    while (1)
    {
#if (MYST_INTERRUPT_WITH_SIGNAL == 1)
        /* Interrupt threads blocked in syscalls on the target */
        myst_spin_lock(&process->thread_group_lock);
        {
            for (t = process->main_process_thread; t; t = t->group_next)
            {
                if (t != process->main_process_thread && t != thread)
                    myst_interrupt_thread(t);
            }
        }
        myst_spin_unlock(&process->thread_group_lock);
#elif (MYST_INTERRUPT_WITH_SIGNAL == -1)
        // Wake up any polls that may be waiting in the host
        myst_tcall_poll_wake();
#else
#error "MYST_INTERRUPT_WITH_SIGNAL undefined"
#endif

        /* We may have had pipes on their way to blocking since the last trigger
         * so lets do it again to be sure */
        if (process->fdtable)
        {
            myst_spin_lock(&process->fdtable->lock);
            myst_fdtable_interrupt(process->fdtable);
            myst_spin_unlock(&process->fdtable->lock);
        }

        /* wait for all other threads except ours and the process thread to go
         * away */
        myst_spin_lock(&process->thread_group_lock);
        for (t = process->main_process_thread; t != NULL; t = t->group_next)
        {
            if (t != process->main_process_thread && t != thread)
            {
                if (myst_get_trace())
                {
                    myst_eprintf(
                        "kernel: still waiting for child %d to be killed, "
                        "waiting_on_event: %d\n",
                        t->tid,
                        t->signal.waiting_on_event);
                }
                if (t->signal.waiting_on_event)
                    myst_tcall_wake(t->event);
                break;
            }
        }
        myst_spin_unlock(&process->thread_group_lock);

        // DO NOT ACCESS CONTENTS OF THREAD!
        // it may already be freed! We are not in the lock any more
        if (t == NULL)
            break;

        myst_sleep_msec(10, false);
    }

    return count;
}

int myst_set_thread_name(myst_thread_t* thread, const char* n)
{
    int ret = 0;

    if (!thread || !n)
        ERAISE(-EINVAL);

    /* Copy at most 15 bytes */
    strncpy(thread->name, n, sizeof(thread->name) - 1);
    /* Set null terminator if string pointed by n
        longer than the 16-byte fixed buffer for thread->name */
    if (strlen(n) >= sizeof(thread->name) - 1)
    {
        thread->name[sizeof(thread->name) - 1] = '\0';
    }

done:
    return ret;
}

/* Send SIGHUP to child processes */
int myst_send_sighup_child_processes(myst_process_t* process)
{
    pid_t pid = process->pid;

    myst_spin_lock(&myst_process_list_lock);

    // first processes left
    myst_process_t* p = process->prev_process;
    while (p)
    {
        if (p->ppid == pid)
            myst_signal_deliver(p->main_process_thread, SIGHUP, NULL);

        p = p->prev_process;
    }

    // now processes right
    p = process->next_process;
    while (p)
    {
        if (p->ppid == pid)
            myst_signal_deliver(p->main_process_thread, SIGHUP, NULL);

        p = p->next_process;
    }
    myst_spin_unlock(&myst_process_list_lock);

    return 0;
}

void myst_wait_on_child_processes(myst_process_t* process)
{
    pid_t pid = process->pid;
    myst_process_t* p;

    do
    {
        myst_spin_lock(&myst_process_list_lock);

        // first processes left
        p = process->prev_process;
        while (p)
        {
            if (p->ppid == pid)
                break;

            p = p->prev_process;
        }

        if (p == NULL)
        {
            // now processes right
            p = process->next_process;
            while (p)
            {
                if (p->ppid == pid)
                    break;

                p = p->next_process;
            }
        }

        myst_spin_unlock(&myst_process_list_lock);

        if (p == NULL)
            break;

        myst_eprintf("process %d waiting for child %d\n", process->pid, p->pid);

        myst_sleep_msec(10, false);

    } while (1);
}

int myst_interrupt_thread(myst_thread_t* thread)
{
    long ret = 0;

    if (!thread)
        ERAISE(-EINVAL);

    ECHECK(myst_tcall_interrupt_thread(thread->target_tid));

done:
    return ret;
}

int myst_set_signal_delivery_altstack(myst_thread_t* thread, size_t stack_size)
{
    int ret = 0;
    void* stack = NULL;

    if (!thread || thread->signal_delivery_altstack ||
        thread->signal_delivery_altstack_size)
        ERAISE(-EINVAL);

    if (stack_size % PAGE_SIZE)
        ERAISE(-EINVAL);

    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    stack = (void*)myst_mmap(NULL, stack_size + PAGE_SIZE, prot, flags, -1, 0);

    if ((long)stack < 0)
        ERAISE(-ENOMEM);

    /* Make the first page as the guard page */
    ECHECK(myst_mprotect(stack, PAGE_SIZE, PROT_NONE));

    thread->signal_delivery_altstack = stack;
    thread->signal_delivery_altstack_size = stack_size + PAGE_SIZE;

    /* the stack is not used by users, no need to do myst_mman_pids_set */

    myst_tcall_td_set_exception_handler_stack(
        (void*)thread->target_td,
        (void*)((uint64_t)stack + PAGE_SIZE),
        stack_size);

done:
    return ret;
}

int myst_clear_signal_delivery_altstack(myst_thread_t* thread)
{
    int ret = 0;

    if (!thread)
        ERAISE(-EINVAL);

    myst_tcall_td_set_exception_handler_stack(
        (void*)thread->target_td, NULL, 0);

    ECHECK(myst_munmap(
        (void*)thread->signal_delivery_altstack,
        thread->signal_delivery_altstack_size));

    thread->signal_delivery_altstack = NULL;
    thread->signal_delivery_altstack_size = 0;

done:
    return ret;
}
