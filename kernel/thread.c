// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <libos/assume.h>
#include <libos/atexit.h>
#include <libos/atomic.h>
#include <libos/cond.h>
#include <libos/eraise.h>
#include <libos/fdtable.h>
#include <libos/fsgs.h>
#include <libos/futex.h>
#include <libos/kernel.h>
#include <libos/lfence.h>
#include <libos/mmanutils.h>
#include <libos/options.h>
#include <libos/panic.h>
#include <libos/printf.h>
#include <libos/setjmp.h>
#include <libos/spinlock.h>
#include <libos/strings.h>
#include <libos/syscall.h>
#include <libos/tcall.h>
#include <libos/thread.h>
#include <libos/time.h>
#include <libos/times.h>
#include <libos/trace.h>

libos_thread_t* __libos_main_thread;

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

pid_t libos_generate_tid(void)
{
    static pid_t _tid = MIN_TID;
    static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;
    pid_t tid;

    libos_spin_lock(&_lock);
    {
        if (_tid < MIN_TID)
            _tid = MIN_TID;

        tid = _tid++;
    }
    libos_spin_unlock(&_lock);

    return tid;
}

/*
**==============================================================================
**
** cookie map:
**
**     This structure maps cookies to threads. When a thread is created, the
**     kernel passes a cookie to the target (libos_tcall_create_thread).
**     The host creates a new thread and then calls back into the kernel on
**     that thread (libos_run_thread). Rather than passing a thread pointer
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

#define MAX_COOKIE_MAP_ENTRIES 64

typedef struct cookie_map_entry
{
    uint64_t cookie;
    libos_thread_t* thread;
    size_t next1; /* one-based next pointer */
} cookie_map_entry_t;

static cookie_map_entry_t _cookie_map[MAX_COOKIE_MAP_ENTRIES];
static size_t _cookie_map_next;  /* next available entry */
static size_t _cookie_map_free1; /* free list of cookie entries (one-based) */
static libos_spinlock_t _cookie_map_lock;

/* assign a cookie for the given thread pointer and return the cookie */
static uint64_t _get_cookie(libos_thread_t* thread)
{
    uint32_t rand;
    uint64_t cookie;

    /* generate a random number (any value is fine except zero) */
    do
    {
        if (libos_syscall_getrandom(&rand, sizeof(rand), 0) != sizeof(rand))
            libos_panic("getrandom failed");
    } while (rand == 0);

    /* add a new entry to the cookie map */
    libos_spin_lock(&_cookie_map_lock);
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
            libos_panic("cookie map exhausted");
        }

        cookie = ((uint64_t)index << 32) | (uint64_t)rand;

        _cookie_map[index].cookie = cookie;
        _cookie_map[index].thread = thread;
        _cookie_map[index].next1 = 0;
    }
    libos_spin_unlock(&_cookie_map_lock);

    return cookie;
}

/* fetch the cookie form the cookie map, while deleting the entry */
static libos_thread_t* _put_cookie(uint64_t cookie)
{
    uint32_t index;
    libos_thread_t* thread = NULL;

    if (cookie == 0)
        libos_panic("zero-valued cookie");

    libos_lfence();

    /* extract the index from the cookie */
    index = (uint32_t)((cookie & 0xffffffff00000000) >> 32);

    libos_spin_lock(&_cookie_map_lock);
    {
        if (index >= _cookie_map_next)
            libos_panic("bad cookie index");

        if (_cookie_map[index].cookie != cookie)
            libos_panic("cookie mismatch");

        thread = _cookie_map[index].thread;

        /* clear the entry */
        _cookie_map[index].cookie = 0;
        _cookie_map[index].thread = NULL;

        /* add the entry to the free list */
        _cookie_map[index].next1 = _cookie_map_free1;
        _cookie_map_free1 = index + 1;
    }
    libos_spin_unlock(&_cookie_map_lock);

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

static libos_thread_t* _zombies;
static libos_mutex_t _zombies_mutex;
static libos_cond_t _zombies_cond;

static void _free_zombies(void* arg)
{
    (void)arg;

    for (libos_thread_t* p = _zombies; p;)
    {
        libos_thread_t* next = p->next;

        memset(p, 0xdd, sizeof(libos_thread_t));
        free(p);

        p = next;
    }

    _zombies = NULL;
}

void libos_zombify_thread(libos_thread_t* thread)
{
    libos_mutex_lock(&_zombies_mutex);
    {
        static bool _initialized;

        if (!_initialized)
        {
            libos_atexit(_free_zombies, NULL);
            _initialized = true;
        }

        thread->next = _zombies;
        _zombies = thread;

        /* signal waiting threads */
        libos_cond_signal(&_zombies_cond);
    }
    libos_mutex_unlock(&_zombies_mutex);
}

long libos_syscall_wait4(
    pid_t pid,
    int* wstatus,
    int options,
    struct rusage* rusage)
{
    long ret = 0;
    bool locked = false;

    if (rusage)
        ERAISE(-EINVAL);

    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED))
        ERAISE(-EINVAL);

    /* ATTN: process groups not supported yet */
    if (pid == 0 || pid < -1)
        ERAISE(-ENOTSUP);

    libos_mutex_lock(&_zombies_mutex);
    locked = true;

    for (;;)
    {
        /* search the zombie list for a process thread */
        for (libos_thread_t* p = _zombies; p; p = p->next)
        {
            bool match = false;

            if (!libos_is_process_thread(p))
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

        /* wait for signal from libos_zombify_thread() */
        libos_cond_wait(&_zombies_cond, &_zombies_mutex);
    }

done:

    if (locked)
        libos_mutex_unlock(&_zombies_mutex);

    return ret;
}

/*
**==============================================================================
**
** main thread implementation:
**
**==============================================================================
*/

bool libos_valid_td(const void* td)
{
    return td && ((const libos_td_t*)td)->self == td;
}

libos_thread_t* libos_thread_self(void)
{
    uint64_t value;
    libos_assume(libos_tcall_get_tsd(&value) == 0);

    libos_thread_t* thread = (libos_thread_t*)value;
    libos_assume(libos_valid_thread(thread));

    return thread;
}

/* Force the caller stack to be aligned */
__attribute__((force_align_arg_pointer)) static void _call_thread_fn(void)
{
    libos_thread_t* thread = libos_thread_self();
    thread->clone.fn(thread->clone.arg);
}

/* The target calls this from the new thread */
long libos_run_thread(uint64_t cookie, uint64_t event)
{
    libos_thread_t* thread = (libos_thread_t*)_put_cookie(cookie);
    libos_td_t* target_td = libos_get_fsbase();
    libos_td_t* crt_td = NULL;
    bool is_child_thread;

    assert(libos_valid_td(target_td));

    if (__options.have_syscall_instruction)
        libos_set_gsbase(target_td);

    libos_assume(libos_valid_thread(thread));

    is_child_thread = thread->crt_td ? true : false;

    if (is_child_thread)
    {
        crt_td = thread->crt_td;
        libos_assume(libos_valid_td(crt_td));

        /* propagate the canary */
        crt_td->canary = target_td->canary;

        /* generate a thread id for this new thread */
        thread->tid = libos_generate_tid();
    }

    /* set the target into the thread */
    thread->target_td = target_td;

    /* save the host thread event */
    libos_assume(event != 0);
    thread->event = event;

    /* bind this thread to the target thread-descriptor */
    libos_assume(libos_tcall_set_tsd((uint64_t)thread) == 0);

    /* bind thread to the C-runtime thread-descriptor */
    if (is_child_thread)
    {
        /* Set the TID for this thread (sets the tid field) */
        {
            libos_atomic_exchange(thread->clone.ptid, thread->tid);
            const int futex_op = FUTEX_WAKE | FUTEX_PRIVATE;
            libos_syscall_futex(thread->clone.ptid, futex_op, 1, 0, NULL, 0);
        }

        /* Start time tracking for this thread */
        libos_times_start();
    }

    /* Jump back here from exit */
    if (libos_setjmp(&thread->jmpbuf) != 0)
    {
        /* ---------- running C-runtime thread descriptor ---------- */

        assert(libos_gettid() != -1);

        /* restore the target thread descriptor */
        libos_set_fsbase(thread->target_td);

        /* ---------- running target thread descriptor ---------- */

        /* Wake up any thread waiting on ctid */
        if (is_child_thread)
        {
            libos_atomic_exchange(thread->clone.ctid, 0);
            const int futex_op = FUTEX_WAKE | FUTEX_PRIVATE;
            libos_syscall_futex(thread->clone.ctid, futex_op, 1, 0, NULL, 0);
        }

        /* Release memory objects owned by the main/process thread */
        if (!is_child_thread)
        {
            if (thread->fdtable)
            {
                libos_fdtable_free(thread->fdtable);
                thread->fdtable = NULL;
            }

            if (thread->main.exec_stack)
            {
                free(thread->main.exec_stack);
                thread->main.exec_stack = NULL;
            }

            if (thread->main.exec_crt_data)
            {
                libos_munmap(
                    thread->main.exec_crt_data, thread->main.exec_crt_size);
                thread->main.exec_crt_data = NULL;
                thread->main.exec_crt_size = 0;
            }
        }

        libos_zombify_thread(thread);

        {
            libos_assume(_num_threads > 1);
            _num_threads--;
        }

        /* Return to target, which will exit this thread */
    }
    else
    {
        /* ---------- running target thread descriptor ---------- */

        /* set the fsbase to C-runtime */
        if (is_child_thread)
            libos_set_fsbase(crt_td);

        /* ---------- running C-runtime thread descriptor ---------- */

        if (is_child_thread)
        {
            /* use the stack provided by clone() */
            libos_jmp_buf_t env = thread->jmpbuf;
            env.rip = (uint64_t)_call_thread_fn;
            env.rsp = (uint64_t)thread->clone.child_stack;
            env.rbp = (uint64_t)thread->clone.child_stack;
            libos_jump(&env);
        }
        else
        {
            /* use the target stack */
            _call_thread_fn();
        }

        /* unreachable */
    }

    return 0;
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
    libos_thread_t* parent = libos_thread_self();
    libos_thread_t* child;

    if (!fn)
        ERAISE(-EINVAL);

    if (!libos_valid_td(newtls))
        ERAISE(-EINVAL);

    /* Check whether the maximum number of threads has been reached */
    {
        /* if too many threads already running */
        if (_num_threads == __libos_kernel_args.max_threads)
            ERAISE(-EAGAIN);

        _num_threads++;
    }

    /* Create and initialize the child thread struct */
    {
        if (!(child = calloc(1, sizeof(libos_thread_t))))
            ERAISE(-ENOMEM);

        child->magic = LIBOS_THREAD_MAGIC;
        child->fdtable = parent->fdtable;
        child->sid = parent->sid;
        child->ppid = parent->ppid;
        child->pid = parent->pid;
        child->crt_td = newtls;
        child->run_thread = libos_run_thread;

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

    if (libos_tcall_create_thread(cookie) != 0)
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
    libos_thread_t* parent = libos_thread_self();
    libos_thread_t* child;

    if (!fn)
        ERAISE(-EINVAL);

    /* Check whether the maximum number of threads has been reached */
    {
        /* if too many threads already running */
        if (_num_threads == __libos_kernel_args.max_threads)
            ERAISE(-EAGAIN);

        _num_threads++;
    }

    /* Create and initialize the thread struct */
    {
        if (!(child = calloc(1, sizeof(libos_thread_t))))
            ERAISE(-ENOMEM);

        child->magic = LIBOS_THREAD_MAGIC;
        child->fdtable = parent->fdtable;
        child->sid = parent->sid;
        child->ppid = parent->ppid;
        child->pid = libos_generate_tid();
        child->tid = child->pid;
        child->run_thread = libos_run_thread;

        if (libos_fdtable_clone(parent->fdtable, &child->fdtable) != 0)
            ERAISE(-ENOMEM);

        /* save the clone() arguments */
        child->clone.fn = fn;
        child->clone.child_stack = child_stack;
        child->clone.flags = flags;
        child->clone.arg = arg;
    }

    cookie = _get_cookie(child);

    if (libos_tcall_create_thread(cookie) != 0)
        ERAISE(-EINVAL);

    ret = child->pid;

done:
    return ret;
}

long libos_syscall_clone(
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

pid_t libos_gettid(void)
{
    return libos_thread_self()->tid;
}

int libos_get_num_threads(void)
{
    return _num_threads;
}
