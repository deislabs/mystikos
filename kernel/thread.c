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
static myst_mutex_t _zombies_mutex;
static myst_cond_t _zombies_cond;
static size_t _zombies_count;

static void _free_zombies(void* arg)
{
    (void)arg;

    for (myst_thread_t* p = _zombies_head; p;)
    {
        myst_thread_t* next = p->znext;

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
    myst_mutex_lock(&_zombies_mutex);
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
        myst_cond_signal(&_zombies_cond);

        /* if max zombie count, free the least-recently-used zombie */
        if (_zombies_count == MAX_ZOMBIES)
        {
            myst_thread_t* p = _zombies_tail;

            /* remove tail from the list */
            _zombies_tail = _zombies_tail->zprev;
            _zombies_tail->znext = NULL;

            /* remove from groups list */
            if (p->group_prev)
                p->group_prev->group_next = p->group_next;

            if (p->group_next)
                p->group_next->group_prev = p->group_prev;

            /* free the zombie */
            free(p);
        }
        else
        {
            _zombies_count++;
        }
    }
    myst_mutex_unlock(&_zombies_mutex);
}

long myst_syscall_wait4(
    pid_t pid,
    int* wstatus,
    int options,
    struct rusage* rusage)
{
    long ret = 0;
    bool locked = false;
    myst_thread_t* process = myst_find_process_thread(myst_thread_self());

    if (rusage)
        ERAISE(-EINVAL);

    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED))
        ERAISE(-EINVAL);

    /* ATTN: process groups not supported yet */
    if (pid == 0 || pid < -1)
        ERAISE(-ENOTSUP);

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

    myst_mutex_lock(&_zombies_mutex);
    locked = true;

    for (;;)
    {
        /* search the zombie list for a process thread */
        for (myst_thread_t* p = _zombies_head; p; p = p->znext)
        {
            bool match = false;

            if (!myst_is_process_thread(p))
                continue;

            if (pid > 0) /* wait for a specific child process */
            {
                match = p->pid == pid;
            }
            else if (pid == -1) /* wait for any child process */
            {
                match = true;
            }

            if (match)
            {
                if (wstatus)
                    *wstatus = (p->exit_status << 8);

                ret = p->pid;
                goto done;
            }
        }

        if ((options & WNOHANG))
        {
            ret = 0;
            goto done;
        }

        /* wait for signal from myst_zombify_thread() */
        myst_cond_wait(&_zombies_cond, &_zombies_mutex);
    }

done:

    if (locked)
        myst_mutex_unlock(&_zombies_mutex);

    return ret;
}

myst_thread_t* myst_find_thread(int tid)
{
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* target = NULL;
    myst_thread_t* t = NULL;

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
        myst_spin_lock(thread->thread_lock);
        for (t = thread->group_prev; t != NULL; t = t->group_prev)
        {
            if (t->tid == tid)
            {
                target = t;
                break;
            }
        }
        myst_spin_unlock(thread->thread_lock);
    }

    return target;
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
            if (thread->fdtable)
            {
                myst_fdtable_free(thread->fdtable);
                thread->fdtable = NULL;
            }

            myst_signal_free(thread);

            if (thread->main.exec_stack)
            {
                free(thread->main.exec_stack);
                thread->main.exec_stack = NULL;
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

                // unmap the memory containing the thread descriptor; set by
                // __unmapself() when it invoke SYS_unmap.
                if (thread->unmapself_addr)
                {
                    myst_munmap(
                        thread->unmapself_addr, thread->unmapself_length);
                }

                /* unmap any mapping made by the process */
                myst_release_process_mappings(thread->pid);
            }

            free(thread->main.cwd);
            thread->main.cwd = NULL;

            procfs_pid_cleanup(thread->pid);
        }

        myst_zombify_thread(thread);

        /* Send a SIGCHLD to the parent process */
        myst_syscall_kill(thread->ppid, SIGCHLD);

        {
            myst_assume(_num_threads > 1);
            _num_threads--;
        }

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

long myst_run_thread(uint64_t cookie, uint64_t event)
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
    struct run_thread_arg arg = {thread, cookie, event};
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

        myst_thread_t* prev_head_child = parent->group_next;
        myst_spin_lock(parent->thread_lock);
        parent->group_next = child;
        child->group_prev = parent;
        if (prev_head_child)
        {
            child->group_next = prev_head_child;
            prev_head_child->group_prev = child;
        }
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
    myst_thread_t* child;
    struct vars
    {
        char fdpath[PATH_MAX];
    };
    struct vars* v = NULL;

    if (!fn)
        ERAISE(-EINVAL);

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

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
        child->fdtable = parent->fdtable;
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

        if (myst_fdtable_clone(parent->fdtable, &child->fdtable) != 0)
            ERAISE(-ENOMEM);

        if (myst_signal_clone(parent, child) != 0)
            ERAISE(-ENOMEM);

        /* save the clone() arguments */
        child->clone.fn = fn;
        child->clone.child_stack = child_stack;
        child->clone.flags = flags;
        child->clone.arg = arg;

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
        {
            const size_t n = sizeof(v->fdpath);
            snprintf(v->fdpath, n, "/proc/%d/fd", child->pid);
            if (myst_mkdirhier(v->fdpath, 777) != 0)
            {
                myst_eprintf("cannot create the /proc/[pid]/fd directory\n");
                ERAISE(-EINVAL);
            }
        }
    }

    cookie = _get_cookie(child);

    if (myst_tcall_create_thread(cookie) != 0)
        ERAISE(-EINVAL);

    ret = child->pid;

done:

    if (v)
        free(v);

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
    return myst_thread_self()->tid;
}

size_t myst_get_num_threads(void)
{
    return _num_threads;
}

// Send kill signal to each thread in the group, and use the best effort to
// ensure they are stopped.
// Return: the number of still running child threads.
size_t myst_kill_thread_group()
{
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* t = NULL;
    myst_thread_t* tail = NULL;
    size_t count = 0;

    // Find the tail of the doubly linked list.
    myst_spin_lock(thread->thread_lock);
    for (t = thread; t != NULL; t = t->group_next)
    {
        if (t->group_next == NULL)
            tail = t;
    }
    myst_spin_unlock(thread->thread_lock);
    assert(tail);

    // Send termination signal to all running child threads.
    myst_spin_lock(thread->thread_lock);
    for (t = tail; t != NULL; t = t->group_prev)
    {
        if (!myst_is_process_thread(t) && t->status == MYST_RUNNING)
        {
            count++;
            myst_spin_unlock(thread->thread_lock);
            myst_signal_deliver(t, SIGKILL, 0);
            // Wake up the thread from futex_wait if necessary.
            if (t->signal.cond_wait)
                myst_cond_signal(t->signal.cond_wait);
            myst_spin_lock(thread->thread_lock);
        }
    }
    myst_spin_unlock(thread->thread_lock);

    // Wait ~1 second for the child threads to hurry up and exit.
    int i = 0;
    while (i++ < 10)
    {
        myst_spin_lock(thread->thread_lock);
        for (t = tail; t != NULL; t = t->group_prev)
        {
            if (t->status != MYST_KILLED && t->status != MYST_ZOMBIE)
                break;
        }
        myst_spin_unlock(thread->thread_lock);

        if (t == NULL)
            break;

        myst_sleep_msec(1);
    }

    return count;
}

int myst_set_thread_name(myst_thread_t* thread, const char* n)
{
    int ret = 0;

    if (!thread || !n)
        ERAISE(-EINVAL);

    /* Copy atmost 15 bytes */
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
