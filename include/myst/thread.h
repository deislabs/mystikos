// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_THREAD_H
#define _MYST_THREAD_H

#include <signal.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <unistd.h>

#include <myst/assume.h>
#include <myst/bufu64.h>
#include <myst/defs.h>
#include <myst/fdtable.h>
#include <myst/futex.h>
#include <myst/kstack.h>
#include <myst/setjmp.h>
#include <myst/spinlock.h>
#include <myst/tcall.h>
#include <myst/types.h>

#define MYST_THREAD_MAGIC 0xc79c53d9ad134ad4
#define MYST_MAX_MUNNAP_ON_EXIT 5

typedef struct myst_thread myst_thread_t;

typedef struct myst_td myst_td_t;

enum myst_thread_status
{
    MYST_RUNNING = 0,
    MYST_KILLED,
    MYST_ZOMBIE,
};

/* thread descriptor for libc threads (initial fields of struct pthread) */
struct myst_td
{
    struct myst_td* self;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
    uint64_t canary;
    uint64_t tsd; /* pointer to myst_thread_t (within OE gsbase) */
    uint64_t reserved5;
    uint64_t reserved6;
    int errnum;  /* errno: unused Open Enclave */
    int padding; /* unused by Open Enclave */
};

bool myst_valid_td(const void* td);

extern myst_spinlock_t myst_process_list_lock;

typedef struct
{
    uint64_t handler;
    unsigned long flags;
    uint64_t restorer;
    uint64_t mask;
} posix_sigaction_t;

typedef struct myst_robust_list_head
{
    volatile void* volatile head;
    long off;
    volatile void* volatile pending;
} myst_robust_list_head_t;

/* When we have more of than one signal queued we need a list of them. */
struct siginfo_list_item
{
    siginfo_t* siginfo;
    struct siginfo_list_item* next;
};

struct myst_thread
{
    /* MYST_THREAD_MAGIC */
    uint64_t magic;

    /* used by myst_thread_queue_t (condition variables and mutexes) */
    struct myst_thread* qnext;

    /* doubly-linked zombie-list */
    struct myst_thread* znext;
    struct myst_thread* zprev;

    /* the session id (see getsid() function) */
    pid_t sid;

    /* the parent process identifier (inherited from main thread) */
    pid_t ppid;

    /* the process identifier (inherited from main thread) */
    pid_t pid;

    /* unique thread identifier (same as pid for main thread) */
    pid_t tid;

    /* the value returned by gettid() on the target (for this thread) */
    pid_t target_tid;

    /* The exit status passed to SYS_exit */
    int exit_status;

    /* Terminating signal value */
    unsigned terminating_signum;

    /* Timespec at process creation */
    struct timespec start_ts;

    /* Timespec at when the thread last entered userspace */
    struct timespec enter_kernel_ts;

    /* Timespec at when the thread last crossed over to userspace */
    struct timespec leave_kernel_ts;

    /* the C-runtime thread descriptor */
    myst_td_t* crt_td;

    /* the target and thread descriptor */
    myst_td_t* target_td;

    /* called by target to run child theads */
    long (*run_thread)(uint64_t cookie, uint64_t event, pid_t target_tid);

    /* synchronization event from myst_thread_t.run_thread() */
    uint64_t event;

    /* for jumping back on exit */
    myst_jmp_buf_t jmpbuf;

    /* the file-descriptor table is inherited from process thread */
    myst_fdtable_t* fdtable;

    /* arguments passed in from SYS_clone */
    struct
    {
        int (*fn)(void*);
        void* child_stack;
        int flags;
        void* arg;
        pid_t* ptid;  /* null for vfork */
        void* newtls; /* null for vfork */
        pid_t* ctid;  /* null for vfork */

        /* If the clone is vfork mode, we may need to signal the parents
         * initiation thread when an exec or exit is called from the child. */
        /* This is necessary when pseudo fork is in wait_exec_exit mode. This
         * also may be used for actual vfork(). */
        pid_t vfork_parent_pid;
        pid_t vfork_parent_tid;
    } clone;

    /* fields used by main thread (process thread) */
    struct
    {
        /* the stack that was created by myst_exec() */
        void* exec_stack;
        size_t exec_stack_size;

        /* the copy of the CRT data made by myst_exec() */
        void* exec_crt_data;
        size_t exec_crt_size;

        /* lock when enumerating all threads in this process
           while enumerating over thread->group_prev/next */
        myst_spinlock_t thread_group_lock;

        /* use this lock when using */
        /* myst_process_list_lock */
        myst_thread_t* prev_process_thread;
        myst_thread_t* next_process_thread;

        /* process CWD. Can be set on differnt threads so need to protect it too
         */
        char* cwd;
        myst_spinlock_t cwd_lock;

        /* The current umask this process */
        mode_t umask;
        myst_spinlock_t umask_lock;

        /* the process group ID */
        pid_t pgid;

        struct unmap_on_exit
        {
            void* ptr;
            size_t size;
        } unmap_on_exit[MYST_MAX_MUNNAP_ON_EXIT];
        _Atomic size_t unmap_on_exit_used;

    } main;

    volatile _Atomic enum myst_thread_status status;

    /* fields used by signal handling */
    struct
    {
        // the signal handles registered through sigaction and
        // shared by threads in the prcoess.
        posix_sigaction_t* sigactions;

        /* The condition we were waiting on a futex */
        _Atomic bool waiting_on_event;

        /* The mask of blocked signals */
        uint64_t mask;

        /* The pending signals */
        _Atomic uint64_t pending;

        /* The lock to ensure sequential delivery of signals */
        myst_spinlock_t lock;

        /* The list of siginfo_t for pending signals */
        struct siginfo_list_item* siginfos[NSIG - 1];
    } signal;

    // linked list of threads in process
    // lock points to the one in the main thread. Use when
    // iterating over the list.
    myst_spinlock_t* thread_lock;
    struct myst_thread* group_prev;
    struct myst_thread* group_next;

    /* robust list (see SYS_set_robust_list & SYS_get_robust_list) */
    struct myst_robust_list_head* robust_list_head;
    size_t robust_list_len;
    myst_spinlock_t robust_list_head_lock;

    /* thread name */
    char name[16];

    /* process identity */
    uid_t uid;
    gid_t gid;

    /* effective process identity */
    uid_t euid;
    gid_t egid;

    /* effective process identity */
    uid_t savuid;
    gid_t savgid;

    /*  process filesystem identity */
    uid_t fsuid;
    gid_t fsgid;

    /* supplemental groups */
    size_t num_supgid;
    gid_t supgid[NGROUPS_MAX];

    /* the kernel stack that was allocated to handle the exit system call */
    myst_kstack_t* exit_kstack;

    /* the kernel stacks that were allocated to handle the exec system call */
    myst_bufu64_t exec_kstacks;

    /* when fork needs to wait for child to call exec or exit, wait on this
     * fuxtex. Child set to 1 and signals futex. */
    int fork_exec_futex_wait;
};

MYST_INLINE bool myst_valid_thread(const myst_thread_t* thread)
{
    return thread && thread->magic == MYST_THREAD_MAGIC;
}

myst_thread_t* myst_thread_self(void);

void myst_zombify_thread(myst_thread_t* thread);

typedef struct myst_thread_queue
{
    myst_thread_t* front;
    myst_thread_t* back;
} myst_thread_queue_t;

MYST_INLINE size_t myst_thread_queue_size(myst_thread_queue_t* queue)
{
    size_t n = 0;

    for (myst_thread_t* p = queue->front; p; p = p->qnext)
        n++;

    return n;
}

MYST_INLINE void myst_thread_queue_push_back(
    myst_thread_queue_t* queue,
    myst_thread_t* thread)
{
    thread->qnext = NULL;

    if (queue->back)
        queue->back->qnext = thread;
    else
        queue->front = thread;

    queue->back = thread;
}

MYST_INLINE myst_thread_t* myst_thread_queue_pop_front(
    myst_thread_queue_t* queue)
{
    myst_thread_t* thread = queue->front;

    if (thread)
    {
        queue->front = queue->front->qnext;

        if (!queue->front)
            queue->back = NULL;
    }

    return thread;
}

/** Remove a thread from arbitrary position in the queue.
 *  Returns the position in the queue if found. -1 otherwise.
 */
MYST_INLINE int myst_thread_queue_remove_thread(
    myst_thread_queue_t* queue,
    myst_thread_t* thread)
{
    int pos = 0;
    bool found = false;
    myst_thread_t* t = NULL;
    myst_thread_t* prev = NULL;

    for (t = queue->front; t; prev = t, pos++, t = t->qnext)
    {
        if (t == thread)
        {
            found = true;
            if (prev != NULL)
            {
                prev->qnext = t->qnext;
                if (t->qnext == NULL)
                    queue->back = prev;
            }
            else
            {
                queue->front = queue->front->qnext;
                if (queue->front == NULL)
                    queue->back = NULL;
            }
            break;
        }
    }

    // thread->qnext = NULL;
    return found ? pos : -1;
}

MYST_INLINE bool myst_thread_queue_contains(
    myst_thread_queue_t* queue,
    myst_thread_t* thread)
{
    myst_thread_t* p;

    for (p = queue->front; p; p = p->qnext)
    {
        if (p == thread)
            return true;
    }

    return false;
}

MYST_INLINE bool myst_thread_queue_empty(myst_thread_queue_t* queue)
{
    return queue->front ? false : true;
}

MYST_INLINE bool myst_is_process_thread(const myst_thread_t* thread)
{
    return thread && thread->pid == thread->tid;
}

MYST_INLINE myst_thread_t* myst_find_process_thread(myst_thread_t* thread)
{
    myst_thread_t* t = NULL;
    myst_spin_lock(thread->thread_lock);
    for (t = thread; t != NULL && !myst_is_process_thread(t); t = t->group_prev)
        ;
    myst_spin_unlock(thread->thread_lock);
    return t;
}

long myst_run_thread(uint64_t cookie, uint64_t event, pid_t target_tid);

pid_t myst_generate_tid(void);

pid_t myst_gettid(void);

long myst_wait(
    pid_t pid,
    int* wstatus,
    siginfo_t* infop,
    int options,
    struct rusage* rusage);

void myst_wait_on_child_processes(void);

size_t myst_get_num_threads(void);

myst_thread_t* myst_find_thread(int tid);

void myst_fork_exec_futex_wake(myst_thread_t* thread);

size_t myst_kill_thread_group();

long myst_have_child_forked_processes(myst_thread_t* process);
long kill_child_fork_processes(myst_thread_t* process);

MYST_INLINE char* myst_get_thread_name(myst_thread_t* thread)
{
    return thread->name;
}

int myst_set_thread_name(myst_thread_t* thread, const char* n);

/* call the given function on the given stack */
long myst_call_on_stack(void* stack, long (*func)(void* arg), void* arg);

#endif /* _MYST_THREAD_H */
