// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <myst/assume.h>
#include <myst/atexit.h>
#include <myst/atomic.h>
#include <myst/cond.h>
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
#include <myst/signal.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/time.h>
#include <myst/times.h>
#include <myst/trace.h>

//#define TRACE

myst_thread_t* __myst_main_thread;

myst_spinlock_t myst_process_list_lock = MYST_SPINLOCK_INITIALIZER;

/* The total number of threads running (including the main thread) */
static _Atomic(size_t) _num_threads = 1;

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
**     Threads are moved onto the zombie list after exiting.
**
**     ATTN: consider separate process-zombies list (for performance).
**
**==============================================================================
*/

#define MAX_ZOMBIES 64

static myst_thread_t* _zombies_head;
static myst_thread_t* _zombies_tail;
// static myst_mutex_t _zombies_mutex;
// static myst_cond_t _zombies_cond;
static size_t _zombies_count;

static void _free_zombies(void* arg)
{
    (void)arg;

    for (myst_thread_t* p = _zombies_head; p;)
    {
        myst_thread_t* next = p->znext;

        myst_signal_free_siginfos(p);
        memset(p, 0xdd, sizeof(myst_thread_t));
        free(p);

        p = next;
    }

    _zombies_head = NULL;
    _zombies_tail = NULL;
    _zombies_count = 0;
}

void myst_zombify_thread(myst_thread_t* thread)
{
    if (myst_is_process_thread(thread))
    {
        myst_spin_lock(&myst_process_list_lock);
        {
            static bool _initialized;

            if (!_initialized)
            {
                myst_atexit(_free_zombies, NULL);
                _initialized = true;
            }

            thread->znext = _zombies_head;
            thread->zprev = NULL;

            if (_zombies_head)
            {
                _zombies_head->zprev = thread;
                _zombies_head = thread;
            }
            else
            {
                _zombies_head = thread;
                _zombies_tail = thread;
            }

            thread->status = MYST_ZOMBIE;

            /* signal waiting threads */
            /* currently not used */
            // myst_cond_signal(&_zombies_cond);

            _zombies_count++;
        }
        myst_spin_unlock(&myst_process_list_lock);
    }
    else
    {
        thread->status = MYST_ZOMBIE;
    }
}

static bool _wait_matcher(
    MYST_UNUSED const char* type,
    pid_t pid,
    myst_thread_t* our_process,
    myst_thread_t* check_process)
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
            check_process->main.pgid,
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
            check_process->main.pgid,
            match ? "true" : "false");
#endif
    }
    else if (pid == 0) /* wait for any process in our process group */
    {
        match =
            ((check_process->ppid == our_process->pid) &&
             (check_process->main.pgid == our_process->main.pgid));
#ifdef TRACE
        printf(
            "matcher(%s): Wait for any process with our pgid %u: found pid=%u, "
            "ppid=%u, pgid=%u: "
            "%s\n",
            type,
            our_process->main.pgid,
            check_process->pid,
            check_process->ppid,
            check_process->main.pgid,
            match ? "true" : "false");
#endif
    }
    else if (pid < -1) /* specific process group */
    {
        match =
            ((check_process->ppid == our_process->pid) &&
             ((-pid) == check_process->main.pgid));
#ifdef TRACE
        printf(
            "matcher(%s): Wait for specific pgid %u: found pid=%u, ppid=%u, "
            "pgid=%u: %s\n",
            type,
            -pid,
            check_process->pid,
            check_process->ppid,
            check_process->main.pgid,
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
    long ret = -1;
    bool locked = false;
    myst_thread_t* process = myst_find_process_thread(myst_thread_self());
    myst_thread_t* p;

#ifdef TRACE
    printf(
        "***wait4 from process %u, wait for pid %d, WNOHANG=%s)\n",
        process->pid,
        pid,
        ((options & WNOHANG) == WNOHANG) ? "NO HANG" : "HANG");
#endif

    if (rusage)
        ERAISE(-EINVAL);

    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED))
        ERAISE(-EINVAL);

    /* If this is the only process then raise ECHILD */
    {
        myst_spin_lock(&myst_process_list_lock);

        if (process->main.next_process_thread == NULL &&
            process->main.prev_process_thread == NULL)
        {
            myst_spin_unlock(&myst_process_list_lock);
            ERAISE(-ECHILD);
        }

        myst_spin_unlock(&myst_process_list_lock);
    }

    myst_spin_lock(&myst_process_list_lock);
    locked = true;

    for (;;)
    {
        /* search the zombie list for a process thread */
        for (p = _zombies_head; p; p = p->znext)
        {
            myst_assume(myst_is_process_thread(p));

            if (_wait_matcher("zombie", pid, process, p))
            {
                if (wstatus)
                {
                    *wstatus = 0;

                    if (p->terminating_signum)
                    {
                        *wstatus = (p->terminating_signum & 0x7f);
                    }
                    else
                    {
                        *wstatus = ((p->exit_status & 0xff) << 8);
                    }
#ifdef TRACE
                    printf("*** WSTATUS DETAILS: %d\n", *wstatus);
                    printf(
                        "    WIFEXITED (exited through exit(), _exit() or "
                        "return from main): %s\n",
                        WIFEXITED(*wstatus) ? "true" : "false");
                    printf(
                        "    WEXITSTATUS (return code via exit(), _exit() or "
                        "return from main): %u\n",
                        WEXITSTATUS(*wstatus));
                    printf(
                        "    WIFSIGNALED (exited via signal): %s\n",
                        WIFSIGNALED(*wstatus) ? "true" : "false");
                    printf(
                        "    WTERMSIG (signal code to terminate): %u\n",
                        WTERMSIG(*wstatus));
                    printf(
                        "    WCOREDUMP (signaled and dumped core, not "
                        "supported): %s\n",
                        WCOREDUMP(*wstatus) ? "true" : "false");
                    printf(
                        "    WIFSTOPPED (signaled to stop, not supported): "
                        "%s\n",
                        WIFSTOPPED(*wstatus) ? "true" : "false");
                    if (WIFSTOPPED(*wstatus))
                        printf(
                            "    WSTOPSIG (signal code to stop, not "
                            "supported): "
                            "%u\n",
                            WSTOPSIG(*wstatus));
                    printf(
                        "    WIFCONTINUED (signaled to resumed after stop, not "
                        "supported): %s\n",
                        WIFCONTINUED(*wstatus) ? "true" : "false");
#endif
                }
                ret = p->pid;

                // remove from zombie list
                if (p->zprev == NULL)
                {
                    _zombies_head = p->znext;
                }
                else
                {
                    p->zprev->znext = p->znext;
                }
                if (p->znext != NULL)
                    p->znext->zprev = p->zprev;

                if (_zombies_tail == p)
                    _zombies_tail = p->group_prev;

                _zombies_count--;

                // remove from process list
                if (p->main.prev_process_thread)
                    p->main.prev_process_thread->main.next_process_thread =
                        p->main.next_process_thread;
                if (p->main.next_process_thread)
                    p->main.next_process_thread->main.prev_process_thread =
                        p->main.prev_process_thread;

                // free zombie thread
                free(p);

                goto done;
            }
        }

        /* no zombies found, but are there any running childred? If not then
         * ECHILD returned */

        // first processes left
        p = process->main.prev_process_thread;
        while (p && !_wait_matcher("active", pid, process, p))
        {
            p = p->main.prev_process_thread;
        }
        if (p == NULL)
        {
            // now processes right
            p = process->main.next_process_thread;
            while (p && !_wait_matcher("active", pid, process, p))
            {
                p = p->main.next_process_thread;
            }
        }
        if (p == NULL)
        {
#ifdef TRACE
            printf("Returning ECHILD\n");
#endif
            ERAISE(-ECHILD);
        }

        myst_spin_unlock(&myst_process_list_lock);
        locked = false;

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
                process->main.pgid,
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
        myst_sleep_msec(100);
        myst_spin_lock(&myst_process_list_lock);
        locked = true;

        // current implementation does not cause all waiters to wake up
        // myst_cond_wait(&_zombies_cond, &myst_process_list_lock);
    }

done:

    if (locked)
        myst_spin_unlock(&myst_process_list_lock);

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

/* Find the thread that may be waiting for the fork-exec wait and wake it */
void myst_fork_exec_futex_wake(myst_thread_t* thread)
{
    pid_t pid = thread->clone.vfork_parent_pid;
    pid_t tid = thread->clone.vfork_parent_tid;

    myst_thread_t* our_process_thread =
        myst_find_process_thread(myst_thread_self());
    myst_thread_t* waiter = our_process_thread;

    myst_spin_lock(&myst_process_list_lock);
    while (waiter && waiter->pid != pid)
    {
        waiter = waiter->main.prev_process_thread;
    }
    if (waiter == NULL)
    {
        waiter = our_process_thread->main.next_process_thread;
        while (waiter && waiter->pid != pid)
        {
            waiter = waiter->main.next_process_thread;
        }
    }
    myst_spin_unlock(&myst_process_list_lock);

    if (waiter == NULL)
        goto done;

    /* find the waiter */
    {
        myst_spinlock_t* thread_lock = waiter->thread_lock;
        myst_spin_lock(thread_lock);

        while (waiter && waiter->tid != tid)
        {
            waiter = waiter->group_next;
        }

        myst_spin_unlock(thread_lock);
    }

    if (waiter)
    {
        __sync_val_compare_and_swap(&waiter->fork_exec_futex_wait, 0, 1);
        myst_futex_wake(&waiter->fork_exec_futex_wait, 1);
    }

done:
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

        /* generate a thread id for this new thread */
        thread->tid = myst_generate_tid();
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

        /* Start time tracking for this thread */
        myst_times_start();
    }

    /* Jump back here from exit */
    if (myst_setjmp(&thread->jmpbuf) != 0)
    {
        /* ---------- running C-runtime thread descriptor ---------- */

        assert(myst_gettid() != -1);

        /* restore the target thread descriptor */
        myst_set_fsbase(thread->target_td);

        /* ---------- running target thread descriptor ---------- */

        /* release the kernel stack that was passed to SYS_exit if any */
        if (thread->kstack)
            myst_put_kstack(thread->kstack);

        /* Wake up any thread waiting on ctid */
        if (is_child_thread)
        {
            myst_atomic_exchange(thread->clone.ctid, 0);
            const int futex_op = FUTEX_WAKE | FUTEX_PRIVATE;
            myst_syscall_futex(thread->clone.ctid, futex_op, 1, 0, NULL, 0);
        }

        /* Release memory objects owned by the main/process thread */
        if (!is_child_thread)
        {
            /* free all non-process threads */
            {
                myst_thread_t* t = thread->group_next;
                while (t)
                {
                    myst_thread_t* next = t->group_next;
                    if (t != thread)
                    {
                        if (t->status == MYST_RUNNING)
                        {
                            myst_sleep_msec(10);
                            continue;
                        }

                        if (t->group_prev)
                            t->group_prev->group_next = t->group_next;
                        if (t->group_next)
                            t->group_next->group_prev = t->group_prev;
                        myst_signal_free_siginfos(t);
                        free(t);
                    }
                    t = next;
                }
            }
            if (thread->fdtable)
            {
                myst_fdtable_free(thread->fdtable);
                thread->fdtable = NULL;
            }

            myst_signal_free(thread);
            myst_signal_free_siginfos(thread);

            if (thread->main.exec_stack)
            {
                free(thread->main.exec_stack);
                thread->main.exec_stack = NULL;
                thread->main.exec_stack_size = 0;
            }

            if (thread->main.exec_crt_data)
            {
                long r = myst_munmap(
                    thread->main.exec_crt_data, thread->main.exec_crt_size);
                thread->main.exec_crt_data = NULL;
                thread->main.exec_crt_size = 0;

                if (r != 0)
                {
                    myst_eprintf(
                        "%s(%u): myst_munmap() failed", __FILE__, __LINE__);
                }

                /* unmap any mapping made by the process */
                myst_release_process_mappings(thread->pid);
            }

            {
                size_t i = thread->main.unmap_on_exit_used;
                while (i)
                {
                    myst_munmap(
                        thread->main.unmap_on_exit[i - 1].ptr,
                        thread->main.unmap_on_exit[i - 1].size);
                    i--;
                }
            }

            free(thread->main.cwd);
            thread->main.cwd = NULL;

            procfs_pid_cleanup(thread->pid);

            /* Send a SIGCHLD to the parent process */
            myst_syscall_kill(thread->ppid, SIGCHLD);
        }

        {
            myst_assume(_num_threads > 1);
            _num_threads--;
        }

        myst_zombify_thread(thread);

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
    size_t stack_size;
    const size_t stack_alignment = 16;
    const size_t process_stack_size = 65536;
    const size_t regular_stack_size = 8192;
    uint8_t* stack = NULL;

    /* get the thread corresponding to this cookie */
    if (!(thread = _put_cookie(cookie)))
        ERAISE(-EINVAL);

    /* the stack size is determined by the thread type (process or regular) */
    if (myst_is_process_thread(thread))
        stack_size = process_stack_size;
    else
        stack_size = regular_stack_size;

    /* allocate a new stack since the OE caller stack is very small */
    if (!(stack = memalign(stack_alignment, stack_size)))
        ERAISE(-ENOMEM);

    /* run the thread on the transient stack */
    struct run_thread_arg arg = {thread, cookie, event, target_tid};
    ECHECK(myst_call_on_stack(stack + stack_size, _run_thread, &arg));

done:

    if (stack)
        free(stack);

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
    myst_thread_t* parent = myst_thread_self();
    myst_thread_t* child;

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
        if (!(child = calloc(1, sizeof(myst_thread_t))))
            ERAISE(-ENOMEM);

        child->magic = MYST_THREAD_MAGIC;
        child->fdtable = parent->fdtable;
        child->sid = parent->sid;
        child->ppid = parent->ppid;
        child->pid = parent->pid;
        child->crt_td = newtls;
        child->run_thread = myst_run_thread;
        child->thread_lock = parent->thread_lock;
        /* ATTN: we don't take a lock on _num_threads,
            thread names could be duplicates */
        snprintf(
            child->name,
            sizeof(child->name),
            "thread-%ld",
            _num_threads % 99999999);

        // Link up parent, child, and the previous head child of the parent,
        // if there is one, in the same thread group.

        myst_spin_lock(parent->thread_lock);
        child->group_next = parent->group_next;
        child->group_prev = parent;
        if (parent->group_next)
            parent->group_next->group_prev = child;
        parent->group_next = child;
        myst_spin_unlock(parent->thread_lock);

        // Inherit signal dispositions
        child->signal.sigactions = parent->signal.sigactions;

        /* save the clone() arguments */
        child->clone.fn = fn;
        child->clone.child_stack = child_stack;
        child->clone.flags = flags;
        child->clone.arg = arg;
        child->clone.ptid = ptid;
        child->clone.newtls = newtls;
        child->clone.ctid = ctid;
    }

    cookie = _get_cookie(child);

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
    myst_thread_t* parent = myst_thread_self();
    myst_thread_t* child = NULL;

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
        if (!(child = calloc(1, sizeof(myst_thread_t))))
            ERAISE(-ENOMEM);

        child->magic = MYST_THREAD_MAGIC;
        child->sid = parent->sid;
        child->ppid = parent->pid;
        child->pid = myst_generate_tid();
        child->tid = child->pid;
        child->run_thread = myst_run_thread;
        /* ATTN: we don't take a lock on _num_threads,
            thread names could be duplicates */
        snprintf(
            child->name,
            sizeof(child->name),
            "thread-%ld",
            _num_threads % 99999999);

        /* Inherit identity from parent process */
        child->uid = parent->uid;
        child->euid = parent->euid;
        child->savuid = parent->savgid;
        child->fsuid = parent->fsuid;
        child->gid = parent->gid;
        child->egid = parent->egid;
        child->savgid = parent->savgid;
        child->fsgid = parent->fsgid;
        memcpy(child->supgid, parent->supgid, parent->num_supgid);
        child->num_supgid = parent->num_supgid;

        child->main.thread_group_lock = MYST_SPINLOCK_INITIALIZER;
        child->thread_lock = &child->main.thread_group_lock;

        /* Inherit parent current working directory */
        child->main.cwd_lock = MYST_SPINLOCK_INITIALIZER;
        child->main.cwd = strdup(parent->main.cwd);
        if (child->main.cwd == NULL)
            ERAISE(-ENOMEM);

        /* inherit the umask from the parent process */
        child->main.umask = parent->main.umask;

        /* inherit process group ID */
        child->main.pgid = parent->main.pgid;

        if (myst_fdtable_clone(parent->fdtable, &child->fdtable) != 0)
            ERAISE(-ENOMEM);

        if (myst_signal_clone(parent, child) != 0)
            ERAISE(-ENOMEM);

        /* save the clone() arguments */
        child->clone.fn = fn;
        child->clone.child_stack = child_stack;
        child->clone.flags = flags;
        child->clone.arg = arg;

        /* If this is being called as part of a fork() call we may need to use
         * these to notify the parent processes tid to wake up in fork/exec mode
         */
        child->clone.vfork_parent_pid = parent->pid;
        child->clone.vfork_parent_tid = parent->tid;

        /* In case we are going to be used for fork-exec scenario where we need
         * to wait for exec or exit, reset the futex */
        parent->fork_exec_futex_wait = 0;

        myst_thread_t* parent_main_thread = parent;
        if (!myst_is_process_thread(parent))
            parent_main_thread = myst_find_process_thread(parent);

        myst_assume(parent_main_thread != NULL);

        /* add this main process thread to the process linked list */
        myst_spin_lock(&myst_process_list_lock);
        child->main.next_process_thread =
            parent_main_thread->main.next_process_thread;
        if (parent_main_thread->main.next_process_thread)
            parent_main_thread->main.next_process_thread->main
                .prev_process_thread = child;
        child->main.prev_process_thread = parent_main_thread;
        parent_main_thread->main.next_process_thread = child;
        myst_spin_unlock(&myst_process_list_lock);

        /* Create /proc/[pid]/fd directory for new process thread */
        ECHECK(procfs_pid_setup(child->pid));
    }

    cookie = _get_cookie(child);

    if (myst_tcall_create_thread(cookie) != 0)
        ERAISE(-EINVAL);

    ret = child->pid;

    child = NULL;

done:
    if (child)
    {
        if (child->main.cwd)
            free(child->main.cwd);
        free(child);
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

long myst_have_child_forked_processes(myst_thread_t* process)
{
    pid_t pid = process->pid;
    myst_thread_t* p;
    long ret = 0;

    myst_spin_lock(&myst_process_list_lock);
    p = process->main.prev_process_thread;

    while (p)
    {
        if ((p->ppid == pid) && (p->clone.flags & CLONE_VFORK))
        {
            ret = 1;
            break;
        }
        p = p->main.prev_process_thread;
    }

    if (!p)
    {
        p = process->main.next_process_thread;

        while (p)
        {
            if ((p->ppid == pid) && (p->clone.flags & CLONE_VFORK))
            {
                ret = 1;
                break;
            }
            p = p->main.next_process_thread;
        }
    }
    myst_spin_unlock(&myst_process_list_lock);

    return ret;
}

long kill_child_fork_processes(myst_thread_t* process)
{
    if (__myst_kernel_args.fork_mode != myst_fork_pseudo_kill_children)
        return 0;

    myst_spin_lock(&myst_process_list_lock);
    myst_thread_t* p = process->main.prev_process_thread;
    pid_t pid = process->pid;

    /* Send signal to all children that are forks of us */
    while (p)
    {
        if ((p->ppid == pid) && (p->clone.flags & CLONE_VFORK))
            myst_syscall_kill(p->pid, SIGKILL);
        p = p->main.prev_process_thread;
    }

    p = process->main.next_process_thread;

    while (p)
    {
        if ((p->ppid == pid) && (p->clone.flags & CLONE_VFORK))
            myst_syscall_kill(p->pid, SIGKILL);
        p = p->main.next_process_thread;
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
    myst_thread_t* process = myst_find_process_thread(thread);
    myst_thread_t* t = NULL;
    myst_thread_t* tail = NULL;
    size_t count = 0;

    // Find the tail of the doubly linked list.
    myst_spin_lock(process->thread_lock);
    for (t = thread; t != NULL; t = t->group_next)
    {
        if (t->group_next == NULL)
            tail = t;
    }
    myst_spin_unlock(process->thread_lock);
    assert(tail);

    // Send termination signal to all running child threads.
    myst_spin_lock(process->thread_lock);
    for (t = tail; t != NULL; t = t->group_prev)
    {
        if (t != thread && t->status == MYST_RUNNING)
        {
            count++;
            myst_spin_unlock(process->thread_lock);
            myst_signal_deliver(t, SIGKILL, 0);

            // Wake up the thread from futex_wait if necessary.
            if (t->signal.waiting_on_event)
            {
                myst_tcall_wake(t->event);
            }

            myst_spin_lock(process->thread_lock);
        }
    }
    myst_spin_unlock(process->thread_lock);

    // Wait for the child threads to exit.
    while (1)
    {
        // Wake up any polls that may be waiting in the host
        myst_tcall_poll_wake();

        /* We may have had pipes on their way to blocking since the last trigger
         * so lets do it again to be sure */
        myst_spin_lock(&process->fdtable->lock);
        if (process->fdtable)
        {
            myst_fdtable_interrupt(process->fdtable);
        }
        myst_spin_unlock(&process->fdtable->lock);

        myst_spin_lock(process->thread_lock);
        for (t = tail; t != NULL; t = t->group_prev)
        {
            if (t != process && t != thread && t->status != MYST_ZOMBIE)
            {
                if (myst_get_trace())
                {
                    myst_eprintf(
                        "kernel: still waiting for child %d to be killed, "
                        "waiting_on_event: %d\n",
                        t->tid,
                        t->signal.waiting_on_event);
                }
                break;
            }
        }
        myst_spin_unlock(process->thread_lock);

        if (t == NULL)
            break;

        if (t->signal.waiting_on_event)
            myst_tcall_wake(t->event);

        myst_sleep_msec(1);
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
