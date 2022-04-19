// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_THREAD_H
#define _MYST_THREAD_H

#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <unistd.h>

#include <myst/assume.h>
#include <myst/config.h>
#include <myst/defs.h>
#include <myst/fdtable.h>
#include <myst/futex.h>
#include <myst/kstack.h>
#include <myst/limit.h>
#include <myst/setjmp.h>
#include <myst/spinlock.h>
#include <myst/tcall.h>
#include <myst/types.h>

#define MYST_THREAD_MAGIC 0xc79c53d9ad134ad4
#define MYST_MAX_MUNNAP_ON_EXIT 5

/* Typical default value in host operating system's /proc/sys/kernel/pid_max */
#define MYST_PID_MAX 0x8000

/* this signal is used to interrupt threads blocking on host in syscalls */
#define MYST_INTERRUPT_THREAD_SIGNAL (SIGRTMIN + 1)

/* the default size of the signal delivery altstack per thread, which is
 * dynamically allocated if myst_signal_altstack is called */
#define MYST_THREAD_SIGNAL_DELIVERY_ALTSTACK_SIZE (4 * 4096)

typedef struct myst_thread myst_thread_t;
typedef struct myst_process myst_process_t;

extern myst_process_t* myst_main_process;

typedef struct myst_td myst_td_t;

enum myst_thread_status
{
    MYST_RUNNING = 0,
    MYST_KILLED
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

typedef void (*myst_thread_sig_handler_fn)(unsigned signum, void* arg);

typedef struct myst_thread_sig_handler
{
    myst_thread_sig_handler_fn signal_fn;
    void* signal_fn_arg;
    struct myst_thread_sig_handler* previous;
} myst_thread_sig_handler_t;

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

typedef struct myst_itimer myst_itimer_t;

struct myst_process
{
    /* the session id (see getsid() function) */
    pid_t sid;

    /* the parent process identifier (inherited from main thread) */
    pid_t ppid;

    /* the process identifier (inherited from main thread) */
    pid_t pid;

    /* To make sure the exit status and terminating signal number is set only
     * once we use this flag */
    bool exit_status_signum_set;

    /* The exit status passed to SYS_exit */
    int exit_status;

    /* Terminating signal value */
    unsigned terminating_signum;

    /* the stack that was created by myst_exec() */
    void* exec_stack;
    size_t exec_stack_size;

#ifdef MYST_THREAD_KEEP_CRT_PTR
    /* the copy of the CRT data made by myst_exec() */
    void* exec_crt_data;
    size_t exec_crt_size;
#endif

    /* lock when enumerating all threads in this process
        while enumerating over thread->group_prev/next */
    myst_spinlock_t thread_group_lock;

    /* use this lock when using */
    /* myst_process_list_lock */
    myst_process_t* prev_process;
    myst_process_t* next_process;

    /* process CWD. Can be set on differnet threads so need to protect it too
     */
    char* cwd;
    myst_spinlock_t cwd_lock;

    /* The current umask this process */
    mode_t umask;
    myst_spinlock_t umask_lock;

    /* the process group ID */
    pid_t pgid;

    /* Pointer to the main process thread */
    myst_thread_t* main_process_thread;

    /* the file-descriptor table is inherited from process thread */
    myst_fdtable_t* fdtable;

    /* doubly-linked zombie-list */
    struct myst_process* zombie_next;
    struct myst_process* zombie_prev;

    /* If the clone is vfork mode, we may need to signal the parents
     * initiation thread when an exec or exit is called from the child.
     *
     * This is necessary when pseudo fork is in wait_exec_exit mode. This
     * also may be used for actual vfork().
     */
    bool is_pseudo_fork_process;
    bool is_parent_of_pseudo_fork_process;
    pid_t vfork_parent_pid;
    pid_t vfork_parent_tid;
    volatile _Atomic(size_t) num_pseudo_children;

    /* This is a copy of the uid from the main process thread and is only needed
     * when dealing with zombie threads because the main thread is not available
     */
    uid_t process_uid;

    struct
    {
        /* process-wide protection for manipulating signals that use either mask
         * or sigactions*/
        myst_spinlock_t lock;

        // the signal handles registered through sigaction and
        // shared by threads in the prcoess.
        posix_sigaction_t* sigactions;

    } signal;

    /* rlimit values for process */
    struct rlimit rlimits[RLIMIT_NLIMITS];

    /* When a process gets a SIGSTOP the whole process needs to stop
     * until a SIGCONT is received. This futex is used for all threads
     * when they process signals on their own thread. If the futex is
     * set then the thread will wait on the futex until the SIGCONT
     * is received.
     */
    int sigstop_futex;

    /* itimer thread needs to be initialized by the CRT once. This boolean
     * returns if it has not been done yet so it can be initiated. */
    bool itimer_thread_requested;

    /* itimer data. this structure has too many other objects in it that make it
     * hard to not be a pointer so it gets initialized when there are calls. */
    myst_itimer_t* itimer;

    /* Process times for current process system and user time, and kernel and
     * user time for children that have exited and been waited for */
    struct tms process_times;
};

struct myst_thread
{
    /* MYST_THREAD_MAGIC */
    uint64_t magic;

    /* fields used by main thread (process thread) */
    myst_process_t* process;

    /* unique thread identifier (same as pid for main thread) */
    pid_t tid;

    /* thread state -- either running or killed */
    volatile _Atomic enum myst_thread_status thread_status;

    /* the value returned by gettid() on the target (for this thread) */
    pid_t target_tid;

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

    /* used by myst_thread_queue_t (condition variables and mutexes) */
    struct myst_thread* qnext;
    struct myst_thread_queue* queue;
    uint32_t qbitset;

    /* for jumping back on exit */
    myst_jmp_buf_t jmpbuf;

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

    } clone;

    /* fields used by signal handling */
    struct
    {
        /* The condition we were waiting on a futex */
        _Atomic bool waiting_on_event;

        /* The pending signals */
        _Atomic uint64_t pending;

        /* The lock to ensure sequential delivery of signals */
        myst_spinlock_t lock;

        /* The mask of blocked signals (can be set via sigprocmask or be
         * temporarily set during handling a signal) */
        uint64_t mask;

        /* The mask that keeps the copy of mask member set by sigprocmask,
         * which is used to restore the mask member after signal handler
         * finishes (either return to kernel or via iret instruction). */
        uint64_t original_mask;

        /* The list of siginfo_t for pending signals */
        struct siginfo_list_item* siginfos[NSIG - 1];

        /* The alternative stack for signal handlers */
        stack_t altstack;

        /* If a terminating signal is generated inside the kernel this signal
         * handler is called for the thread if present before calling the actual
         * default terminating signal handler. A terminating signal is one which
         * does not have a process sigaction registered by the application, or
         * is a SIGKILL or SIGSTOP. Each default signal handler needs to call
         * the previously registered one.
         */
        myst_thread_sig_handler_t* thread_sig_handler;
    } signal;

    /* The alternative stack used by OE runtime to deliver signals, which is set
     * only when the program sets the alternative signal stack via sigaltstack.
     * The stack is required to handle stack overflow exceptions. */
    void* signal_delivery_altstack;
    size_t signal_delivery_altstack_size;

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

    /* the kernel stack that were allocated to handle the exec system call */
    myst_kstack_t* exec_kstack;

    /* when fork needs to wait for child to call exec or exit, wait on this
     * fuxtex. Child set to 1 and signals futex. */
    int fork_exec_futex_wait;

    /* the temporary stack that was allocated to initialize a user thread */
    void* entry_stack;
    size_t entry_stack_size;

    /* The copy of rsp before switching to the kernel stack during the
     * most recent syscall invocation. For the case of delayed signal
     * handling (i.e., calling myst_signal_process at the syscall layer),
     * the kernel will execute the user signal handler with this rsp instead
     * of using kernal stack. */
    uint64_t user_rsp;

    /* If we have a mapping that is the thread stack then we cannot free it
     * until we return the thread to the kernel for shutting down. There may
     * also be unmappings to the middle of the stack, and those have to be
     * deferred until the thread shuts down also. There are other scenarios
     * where we find it hard to clean up a mappings safely and so they may also
     * need to be deferred too.
     */
    struct unmap_on_exit
    {
        void* ptr;
        size_t size;
    } unmap_on_exit[MYST_MAX_MUNNAP_ON_EXIT];
    _Atomic size_t unmap_on_exit_used;

    // When a thread calls pause(), the calling thread waits on this futex.
    // Another thread or process sending a signal to the waiting thread
    // will wake it up. pause_futex=0 means futex unavailable; 1 means
    // available.
    int pause_futex;
};

MYST_INLINE bool myst_valid_thread(const myst_thread_t* thread)
{
    return thread && thread->magic == MYST_THREAD_MAGIC;
}

myst_thread_t* myst_thread_self(void);
myst_process_t* myst_process_self(void);

void myst_zombify_process(myst_process_t* process);
MYST_INLINE bool myst_is_zombied_process(myst_process_t* process)
{
    return (process->main_process_thread == NULL) ? true : false;
}

typedef struct myst_thread_queue
{
    myst_thread_t* front;
    myst_thread_t* back;
} myst_thread_queue_t;

MYST_INLINE size_t myst_thread_queue_size(myst_thread_queue_t* queue)
{
    size_t n = 0;

    for (const myst_thread_t* p = queue->front; p; p = p->qnext)
        n++;

    return n;
}

MYST_INLINE void __myst_thread_queue_push_back(
    myst_thread_queue_t* queue,
    myst_thread_t* thread,
    uint32_t bitset)
{
    assert(thread->queue == NULL);
    assert(thread->qnext == NULL);

    thread->qnext = NULL;
    thread->qbitset = bitset;

    if (queue->back)
        queue->back->qnext = thread;
    else
        queue->front = thread;

    queue->back = thread;
    thread->queue = queue;
}

MYST_INLINE myst_thread_t* __myst_thread_queue_pop_front(
    myst_thread_queue_t* queue,
    uint32_t* bitset)
{
    myst_thread_t* thread = queue->front;

    if (thread)
    {
        queue->front = queue->front->qnext;

        if (!queue->front)
            queue->back = NULL;

        if (bitset)
            *bitset = thread->qbitset;

        thread->queue = NULL;
        thread->qnext = NULL;
        thread->qbitset = 0;
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

    if (found)
    {
        thread->queue = NULL;
        thread->qnext = NULL;
        return pos;
    }

    return -1;
}

/** Find and remove up to `n` threads from the queue such that
 * <waiting bitset> & <passed in bitset> != 0.
 * Removed threads are placed in the `matches` queue.
 */
MYST_INLINE int myst_thread_queue_search_remove_bitset(
    myst_thread_queue_t* queue,
    myst_thread_queue_t* matches,
    size_t n,
    uint32_t bitset);

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
    return thread && thread == thread->process->main_process_thread;
}

MYST_INLINE myst_process_t* myst_find_process(myst_thread_t* thread)
{
    return thread->process;
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

void myst_wait_on_child_processes(myst_process_t* process, bool is_main_thread);

void myst_shutdown_process_thread(
    myst_process_t* process,
    bool is_main_process);

size_t myst_get_num_threads(void);

myst_thread_t* myst_find_thread(int tid);

/* Caller should hold myst_process_list_lock before calling this function. And
 * release it once its done with its use of the process thread pointer.
 * This is done to protect from the process thread descriptor being cleaned up
 * by some other thread.*/
myst_process_t* myst_find_process_from_pid(pid_t pid, bool include_zombies);

void myst_fork_exec_futex_wake(pid_t vfork_parent_pid, pid_t vfork_parent_tid);

size_t myst_kill_thread_group();

bool myst_have_child_forked_processes(myst_process_t* process);
long kill_child_fork_processes(myst_process_t* process);

MYST_INLINE char* myst_get_thread_name(myst_thread_t* thread)
{
    return thread->name;
}

int myst_set_thread_name(myst_thread_t* thread, const char* n);

/* call the given function on the given stack */
long myst_call_on_stack(void* stack, long (*func)(void* arg), void* arg);

/* Send SIGHUP to child processes of given process thread */
int myst_send_sighup_child_processes(
    myst_process_t* process,
    bool is_main_process);

/* Install a thread signal handler to do thread cleanup before the default
 * terminating signal handler is called. Examples of this include unlocking
 * kernel wide locks that may be held while code is executing that may generate
 * a singal.
 */
MYST_INLINE void myst_thread_sig_handler_install(
    myst_thread_sig_handler_t* sig_handler,
    myst_thread_sig_handler_fn sig_fn,
    void* sig_fn_arg)
{
    myst_thread_t* thread = myst_thread_self();
    if (thread->signal.thread_sig_handler)
        sig_handler->previous = thread->signal.thread_sig_handler->previous;
    else
        sig_handler->previous = NULL;
    sig_handler->signal_fn = sig_fn;
    sig_handler->signal_fn_arg = sig_fn_arg;
    thread->signal.thread_sig_handler = sig_handler;
}

/* Uninstall this thread signal handler and restore to the previous */
MYST_INLINE void myst_thread_sig_handler_uninstall(
    myst_thread_sig_handler_t* sig_handler)
{
    myst_thread_t* thread = myst_thread_self();
    thread->signal.thread_sig_handler = sig_handler->previous;
}

MYST_INLINE void myst_thread_queue_push_back(
    myst_thread_queue_t* queue,
    myst_thread_t* thread)
{
    __myst_thread_queue_push_back(queue, thread, FUTEX_BITSET_MATCH_ANY);
}

MYST_INLINE void myst_thread_queue_push_back_bitset(
    myst_thread_queue_t* queue,
    myst_thread_t* thread,
    uint32_t bitset)
{
    __myst_thread_queue_push_back(queue, thread, bitset);
}

MYST_INLINE myst_thread_t* myst_thread_queue_pop_front(
    myst_thread_queue_t* queue)
{
    return __myst_thread_queue_pop_front(queue, NULL);
}

MYST_INLINE myst_thread_t* myst_thread_queue_pop_front_bitset(
    myst_thread_queue_t* queue,
    uint32_t* bitset)
{
    return __myst_thread_queue_pop_front(queue, bitset);
}

MYST_INLINE int myst_thread_queue_search_remove_bitset(
    myst_thread_queue_t* queue,
    myst_thread_queue_t* matches,
    size_t n,
    uint32_t bitset)
{
    if (!queue || !matches)
        return -1;

    myst_thread_t* t = queue->front;
    myst_thread_t* prev = NULL;

    size_t num_found = 0;

    while (t)
    {
        if (num_found >= n)
            break;

        myst_thread_t* next = t->qnext;
        if (t->qbitset & bitset)
        {
            num_found++;
            if (prev != NULL)
            {
                prev->qnext = next;
            }
            else
            {
                queue->front = queue->front->qnext;
            }
            if (next == NULL)
                queue->back = prev;

            uint32_t tmp_bitset = t->qbitset;
            t->qbitset = 0;
            t->queue = NULL;
            t->qnext = NULL;
            myst_thread_queue_push_back_bitset(matches, t, tmp_bitset);
        }
        else
        {
            prev = t;
        }

        t = next;
    }

    return num_found;
}

int myst_interrupt_thread(myst_thread_t* thread);

int myst_set_signal_delivery_altstack(myst_thread_t* thread, size_t stack_size);

int myst_clear_signal_delivery_altstack(myst_thread_t* thread);

#endif /* _MYST_THREAD_H */
