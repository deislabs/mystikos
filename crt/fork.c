#define hidden __attribute__((__visibility__("hidden")))

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread_impl.h>

#include <myst/kernel.h>
#include <myst/round.h>
#include <myst/setjmp.h>
#include <myst/syscallext.h>

/* Locking functions used by MUSL to manage libc.threads_minus_1 */
void __tl_lock(void);
void __tl_unlock(void);

static void _set_fsbase(void* p)
{
    if (syscall(SYS_set_thread_area, p) < 0)
    {
        fprintf(stderr, "syscall(SYS_set_thread_area, p) failed\n");
        abort();
    }
}

/*
**==============================================================================
**
** myst_get_current_stack()
**
** the main thread stack of all processes are created in the kernel, and all
** other process threads created by pthread_create are done in the CRT itself.
** In the case of the pthread_create threads the stack is populated in the
** pthread structure. The main process stack is not, so we need to call into
** the kernel to get the main process thread stack.
**
**==============================================================================
*/
void myst_get_current_stack(void** stack, size_t* stack_size)
{
    struct pthread* self = __pthread_self();

    if (self->stack && self->stack_size)
    {
        *stack = (uint8_t*)self->stack - self->stack_size;
        *stack_size = self->stack_size;
    }
    else
    {
        const long n = SYS_myst_get_process_thread_stack;

        if (syscall(n, stack, stack_size) != 0)
        {
            fprintf(stderr, "cannot retrieve parent stack\n");
            abort();
        }
    }
}

/*
**==============================================================================
**
** _create_child_pthread_and_copy_stack()
**
** Create a new thread context from the current thread and return a pointer to
** the new pthread structure. The pthread has the following layout.
**
**     [guard|stack|tls|tsd]
**
** Or:
**     [ guard ]                td->guard_size | __default_guardsize
**     [ stack ]                td->stack_size | __default_stacksize
**     [ tls area | tcb ]       __libc.tls_size
**     [ tsd area ]             __pthread_tsd_size
**
**==============================================================================
*/

struct pthread* _create_child_pthread_and_copy_stack(
    void* parent_stack,
    size_t parent_stack_size)
{
    size_t size;
    size_t size_rounded;
    struct pthread* self = __pthread_self();
    struct pthread* new;
    uint8_t* map;
    uint8_t* tsd;
    uint8_t* tls;
    uint8_t* stack;       /* bottom */
    uint8_t* stack_limit; /* top */
    size_t guard_size;
    void* process_stack = NULL;

    guard_size = self->guard_size ? self->guard_size : __default_guardsize;
    size =
        guard_size + parent_stack_size + __libc.tls_size + __pthread_tsd_size;

    myst_round_up(size, PAGE_SIZE, &size_rounded);

    /* The mmapped memory will be marked by Mystikos kernel as owned by the
     * parent process, instead of the child process, or the kernel. During child
     * process exit, the memory will be unmapped. The process memory management
     * logic that unmaps memory regions still owned by the parent process at
     * parent process exit relies specific logic during child process exit to
     * clear the ownership indication. If any part of the relevant design
     * changes, the implementaiton needs to be reconsidered */
    if ((map = mmap(
             NULL,
             size_rounded,
             PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE,
             -1,
             0)) == MAP_FAILED)
        return NULL;

    /* [guard|stack|tls|tsd] */
    tsd = map + size - __pthread_tsd_size;
    tls = tsd - __libc.tls_size;
    stack = tsd - __libc.tls_size;
    stack_limit = stack - parent_stack_size;

    new = __copy_tls(tls);
    new->self = new;
    new->map_base = map;
    new->map_size = size;
    new->stack = stack;
    new->stack_size = stack - stack_limit;
    new->guard_size = guard_size;
    new->self = new;
    new->tsd = (void*)tsd;
    memcpy(new->tsd, self->tsd, __pthread_tsd_size);

    new->detach_state = DT_DETACHED;
    new->robust_list.head = &new->robust_list.head;
    new->canary = self->canary;
    new->sysinfo = self->sysinfo;
    new->locale = self->locale;

    /* copy over the stack if any */
    memcpy(stack_limit, parent_stack, parent_stack_size);

    return new;
}

struct thread_args
{
    _Atomic(int) refcount;
    myst_jmp_buf_t env;
    void* child_sp;
    void* child_bp;
    volatile pid_t pid;
    struct pthread* child_pthread;
    uint64_t canary;

    // pthread memory and stack needs freeing on process exit
    struct mmap_info
    {
        void* mmap_ptr;
        size_t mmap_ptr_size;
    } unmap_on_exit;
};

/* internal musl function */
extern int __clone(int (*func)(void*), void* stack, int flags, void* arg, ...);

static bool _within(const void* data, size_t size, const void* ptr)
{
    const uint8_t* start = data;
    const uint8_t* end = start + size;
    const uint8_t* p = ptr;
    bool flag = p >= start && p < end;
    return flag;
}

/*
**==============================================================================
**
** _fixup_frame_pointers()
**
** This function takes the new copy of the parent threads stack that the child
** forked process will use.
** The structure of the stack has the following entries for each function in
** the call stack:
**
** <args to function>
** <function return address>
** <current value of rbp on entry to this function, AKA frame pointer>
** <local variables>
**
** The rbp pointers, AKA frame pointer, is currently a pointer into the parent
** process stack and not a pointer into the new child stack.
**
** This function traverses the frame pointers and fixes it up to be relative
** to the child stack.
**
** We start by calculating the delta between the parent and child stack, then
** use that delta on each frame pointer within the child stack to fix it up.
**
** Often when we get to the start of the stack the final frame pointer is NULL.
** However sometimes we hit a rogue frame pointer. This could be due to stack
** stack stitching, could be due to code being built without frame pointers,
** or some unknown reason. Frame walking is not a perfect art form and debuggers
** use this and debug symbols to work their magic, but we only have the frame
** pointer. Therefore if a pointer is out of range we stop and hope we got
** enough of the stack to work.
**==============================================================================
*/
static int _fixup_frame_pointers(
    const void* parent_sp,
    const void* parent_bp,
    void* parent_stack,
    size_t parent_stack_size,
    void* child_stack,
    size_t child_stack_size,
    void** child_sp_out,
    void** child_bp_out)
{
    int ret = -1;
    const ptrdiff_t delta = (uint8_t*)parent_stack - (uint8_t*)child_stack;
    const void* pbp = parent_bp;
    void* cbp = (uint8_t*)pbp - delta;

    if (!_within(parent_stack, parent_stack_size, parent_sp))
    {
        assert("parent stack pointer out of range" == NULL);
        goto done;
    }

    if (!_within(parent_stack, parent_stack_size, parent_bp))
    {
        assert("parent base pointer out of range" == NULL);
        goto done;
    }

    if (!_within(parent_stack, parent_stack_size, *(void**)pbp))
    {
        assert("contents of parent base pointer out of range" == NULL);
        goto done;
    }

    if (!_within(child_stack, child_stack_size, cbp))
    {
        assert("child base pointer out of range" == NULL);
        goto done;
    }

    for (size_t i = 0; pbp; i++)
    {
        *(uint64_t*)cbp -= delta;

        pbp = *(void**)pbp;

        if (!pbp)
            break;

        cbp = *(void**)cbp;

        if (!_within(parent_stack, parent_stack_size, pbp))
        {
            break;
        }

        if (!_within(parent_stack, parent_stack_size, *(void**)pbp))
        {
            break;
        }

        if (!_within(child_stack, child_stack_size, cbp))
        {
            break;
        }

        assert((uint8_t*)cbp + delta == pbp);
    }

    *child_sp_out = (uint8_t*)parent_sp - delta;
    *child_bp_out = (uint8_t*)parent_bp - delta;

    ret = 0;

done:
    return ret;
}

uint64_t myst_get_canary()
{
    return __pthread_self()->canary;
}

static int _child_func(void* arg)
{
    struct thread_args* args = (struct thread_args*)arg;
    args->env.rsp = (uint64_t)args->child_sp;
    args->env.rbp = (uint64_t)args->child_bp;

    _set_fsbase(args->child_pthread);

    // set_fsbase is changing the canary from what it should be. Change it back
    // to what we expect it to be
    args->child_pthread->canary = args->canary;

    /* set the fsbase register to point to the child_td */
    args->child_pthread->tid = getpid();

    /* set the pid that the parent is waiting on */
    args->pid = getpid();

    /* queue up the cleanup of these memory regions for this process exit */
    /* We cannot safely free the new stack safely because the freeing will
     * return to the same stack before next syscall to exit. */
    syscall(
        SYS_myst_unmap_on_exit,
        args->unmap_on_exit.mmap_ptr,
        args->unmap_on_exit.mmap_ptr_size);

    /* jump back but on the new child stack */
    myst_longjmp(&args->env, 1);
    return 0;
}

static pthread_key_t _called_by_vfork_key;
static pthread_once_t _called_by_vfork_key_once = PTHREAD_ONCE_INIT;

static void _init_called_by_fork(void)
{
    pthread_key_create(&_called_by_vfork_key, NULL);
}

static uint64_t _get_called_by_vfork(void)
{
    pthread_once(&_called_by_vfork_key_once, _init_called_by_fork);
    return (uint64_t)pthread_getspecific(_called_by_vfork_key);
}

static void _set_called_by_vfork(uint64_t value)
{
    pthread_once(&_called_by_vfork_key_once, _init_called_by_fork);
    pthread_setspecific(_called_by_vfork_key, (void*)value);
}

__attribute__((__returns_twice__)) pid_t myst_fork(void)
{
    pid_t pid = 0;
    myst_jmp_buf_t env;
    struct thread_args* args = NULL;
    myst_fork_mode_t fork_mode = myst_fork_none;

    /* if called by vfork(), then use myst_fork_pseudo_wait_for_exit_exec */
    if (_get_called_by_vfork())
    {
        fork_mode = myst_fork_pseudo_wait_for_exit_exec;
        _set_called_by_vfork(0);
    }
    else
    {
        myst_fork_info_t arg = MYST_FORK_INFO_INITIALIZER;

        if (syscall(SYS_myst_get_fork_info, &arg) < 0)
            return -ENOSYS;

        fork_mode = arg.fork_mode;
    }

    /* fail if fork-mode is still none */
    if (fork_mode == myst_fork_none)
        return -ENOTSUP;

    args = calloc(1, sizeof(struct thread_args));
    if (args == NULL)
    {
        return -ENOMEM;
    }
    args->refcount = 1; // set to 1 until we launch the child

    if (myst_setjmp(&env) == 0) /* parent */
    {
        const void* parent_sp = (const void*)env.rsp;
        const void* parent_bp = (const void*)env.rbp;
        void* sp = NULL;
        void* bp = NULL;
        const int clone_flags = CLONE_VM | CLONE_VFORK | SIGCHLD;
        long tmp_ret;
        struct pthread* child_pthread;
        void* parent_stack;
        void* stack;
        size_t stack_size;
        size_t parent_stack_size;

        myst_get_current_stack(&parent_stack, &parent_stack_size);

        if (!(child_pthread = _create_child_pthread_and_copy_stack(
                  parent_stack, parent_stack_size)))
            return -ENOMEM;

        stack = (uint8_t*)child_pthread->stack - child_pthread->stack_size;
        stack_size = child_pthread->stack_size;

        assert(stack_size == parent_stack_size);

        if (_fixup_frame_pointers(
                parent_sp,
                parent_bp,
                parent_stack,
                parent_stack_size,
                stack,
                stack_size,
                &sp,
                &bp) != 0)
        {
            munmap(child_pthread->map_base, child_pthread->map_size);
            return -ENOMEM;
        }

        // the map region is probably aligned, but to be sure...
        size_t mmap_rounded_size;
        myst_round_up(child_pthread->map_size, PAGE_SIZE, &mmap_rounded_size);

        memcpy(&args->env, &env, sizeof(args->env));
        args->refcount = 2; // one for child, one for parent
        args->child_sp = sp;
        args->child_bp = bp;
        args->child_pthread = child_pthread;
        args->unmap_on_exit.mmap_ptr = child_pthread->map_base;
        args->unmap_on_exit.mmap_ptr_size = mmap_rounded_size;
        args->canary = args->child_pthread->canary;

        // Increment thread count. For regular threads, this is done by MUSL's
        // pthread_create. Since the child process's thread is created via clone
        // instead of pthread_create, the thread count must be incremented
        // manually here.
        __tl_lock();
        __libc.threads_minus_1++;
        __tl_unlock();

        if ((tmp_ret = __clone(_child_func, sp, clone_flags, args)) < 0)
        {
            // restore thread count
            {
                __tl_lock();
                __libc.threads_minus_1--;
                __tl_unlock();
            }
            munmap(child_pthread->map_base, child_pthread->map_size);
            free(args);
            return tmp_ret;
        }

        {
            /* wait for child to set args->pid */
            struct timespec req;
            req.tv_sec = 0;
            req.tv_nsec = 1000;
            while (args->pid == 0)
                nanosleep(&req, NULL);

            pid = args->pid;

            /* Wait if fork mode requires it */
            if (fork_mode == myst_fork_pseudo_wait_for_exit_exec)
            {
                /* wait for the child process to shutdown */
                syscall(SYS_myst_fork_wait_exec_exit);
            }
            else
            {
                /* Sleep enough to allow the child to return first. If an
                 * application assigns the return of fork() to a global variable
                 * then there is contention and the child or parent may win.
                 * This can cause the parent to not know the child pid and all
                 * sorts can fail. This sleep should be enough to let the child
                 * finish first. */
                syscall(SYS_sched_yield);
                syscall(SYS_sched_yield);
                syscall(SYS_sched_yield);
                syscall(SYS_sched_yield);
                syscall(SYS_sched_yield);
            }
        }
    }
    else /* child */
    {
        pid = 0;
    }

    if (--args->refcount == 0)
        free(args);

    return pid;
}

/*
**==============================================================================
**
** vfork()
**
** The vfork() and fork() Mystikos implementations are equivalent except
** that vfork() suspends execution of the calling thread until the child
** either calls exec or _exit. POSIX (The Open Group) specifies that
** vfork() and fork() are equivalent but that the behavior is undefined
** if the child process performs any of the following.
**
**     (1) modifies any data other than a variable of type pid_t used
**         to store the return value from vfork(), or
**     (2) returns from the function in which vfork() was called, or
**     (3) calls any other function before successfully calling _exit()
**         or one of the exec family of functions.
**
** Linux goes further by suspending execution of the calling thread
** until the child process either calls _exit or one of the exec family of
** functions (else parent-process data modifications would be visible to the
** child).
**
** Note that unlike Linux, child modifications of the stack are not visible
** to the parent. But any application that relies on such undefined behavior
** is badly-behaved and non-portable.
**
**==============================================================================
*/

int vfork(void)
{
    /* fork calls _get_called_by_vfork() */
    _set_called_by_vfork(1);
    return fork();
}
