#include <stdarg.h>
#include <errno.h>
#include <string.h>

#include <openenclave/enclave.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/stdlib.h>

#include "pthread_impl.h"
#include "stdio_impl.h"

#include "posix_thread.h"
#include "posix_io.h"
#include "posix_syscall.h"
#include "posix_spinlock.h"
#include "posix_mman.h"
#include "posix_trace.h"
#include "posix_futex.h"
#include "posix_futex.h"
#include "posix_ocalls.h"
#include "posix_signal.h"
#include "posix_mutex.h"
#include "posix_trace.h"
#include "posix_panic.h"

#include "posix_warnings.h"

#define MAGIC 0x6a25f0aa

static posix_spinlock_t _lock;

/* The thread info structure for the main thread */
static posix_thread_t _main_thread;

static oe_thread_data_t* _get_oetd(void)
{
    oe_thread_data_t* oetd;

    __asm__("mov %%fs:0,%0" : "=r" (oetd));

    return oetd;
}

posix_thread_t* posix_self(void)
{
    oe_thread_data_t* oetd;

    if (!(oetd = _get_oetd()))
        return NULL;

    return (posix_thread_t*)(oetd->__reserved_0);
}

static int _set_thread_info(posix_thread_t* thread)
{
    oe_thread_data_t* oetd;

    if (!(oetd = _get_oetd()))
        return -1;

    oetd->__reserved_0 = (uint64_t)thread;
    return 0;
}

int posix_gettid(void)
{
    return posix_self()->tid;
}

int posix_getpid(void)
{
    int retval;

    if (posix_getpid_ocall(&retval) != OE_OK)
        return -EINVAL;

    return retval;
}

extern struct posix_shared_block* __posix_init_shared_block;

extern int __posix_init_tid;

int posix_set_tid_address(int* tidptr)
{
    posix_thread_t* thread;

    if (!(thread = posix_self()))
    {
        oe_assert(false);
        return -EINVAL;
    }

    thread->ctid = tidptr;

#if 0
    int retval;

    if (posix_gettid_ocall(&retval) != OE_OK)
    {
        posix_printf("posix_gettid_ocall() panic\n");
        oe_abort();
    }
#endif

    /* ATTN: assumes that only the main thread calls this */
    int tid = __posix_init_tid;

    return tid;
}

/* This is called only by the main thread. */
int posix_set_thread_area(void* p)
{
    memset(&_main_thread, 0, sizeof(_main_thread));
    _main_thread.magic = MAGIC;
    _main_thread.td = (pthread_t)p;
    _main_thread.shared_block = __posix_init_shared_block;

    _set_thread_info(&_main_thread);

    return 0;
}

struct pthread* posix_pthread_self(void)
{
    posix_thread_t* thread;

    if (!(thread = posix_self()))
        return NULL;

    return thread->td;
}

void posix_unblock_creator_thread(void)
{
    posix_thread_t* self = posix_self();

    if (!self)
        POSIX_PANIC("unexpected");

    self->state = POSIX_THREAD_STATE_STARTED;
    posix_spin_unlock(&self->lock);
}

int posix_run_thread_ecall(
    uint64_t cookie,
    int tid,
    struct posix_shared_block* shared_block)
{
    posix_thread_t* thread = (posix_thread_t*)cookie;

    if (!thread || !oe_is_within_enclave(thread, sizeof(thread)) ||
        thread->magic != MAGIC)
    {
        POSIX_PANIC("unexpected");
    }

    thread->tid = tid;
    thread->shared_block = shared_block;

    _set_thread_info(thread);

    /* Set the TID for this thread */
    a_swap(thread->ptid, tid);

    if (setjmp(thread->jmpbuf) == 0)
    {
        (*thread->fn)(thread->arg);

        /* Never returns. */
        POSIX_PANIC("unexpected");
    }

    return 0;
}

int posix_clone(
    int (*fn)(void *),
    void* child_stack,
    int flags,
    void* arg,
    ...)
{
    int ret = 0;
    va_list ap;

    /* Ignored */
    (void)child_stack;

    va_start(ap, arg);
    pid_t* ptid = va_arg(ap, pid_t*);
    struct pthread* td = va_arg(ap, void*);
    pid_t* ctid = va_arg(ap, pid_t*);
    va_end(ap);

    oe_assert(td != NULL);
    oe_assert(td->self == td);

    /* Create the thread info structure for the new thread */
    posix_thread_t* thread;
    {
        /* ATTN: free this! */
        if (!(thread = oe_calloc(1, sizeof(posix_thread_t))))
        {
            ret = -ENOMEM;
            goto done;
        }

        thread->magic = MAGIC;
        thread->td = td;
        thread->fn = fn;
        thread->arg = arg;
        thread->flags = flags;
        thread->ptid = ptid;
        thread->ctid = ctid;
        thread->state = 0;
    }

    /* The thread will unlock this when it starts */
    posix_spin_lock(&thread->lock);

    /* Ask the host to call posix_run_thread_ecall() on a new thread */
    {
        int retval = -1;
        uint64_t cookie = (uint64_t)thread;

        if (posix_start_thread_ocall(&retval, cookie) != OE_OK)
        {
            ret = -ENOMEM;
            goto done;
        }

        if (retval != 0)
        {
            ret = -ENOMEM;
            goto done;
        }
    }

    /* Wait here for thread to start and unlock this */
    posix_spin_lock(&thread->lock);

    if (thread->state != POSIX_THREAD_STATE_STARTED)
        POSIX_PANIC("unexpected");

done:

    return ret;
}

static void _unlock_file_if_owner(FILE* file)
{
    int tid = posix_self()->tid;
    int value = file->lock;

    if ((value & ~MAYBE_WAITERS) == tid)
    {
        posix_thread_t* owner;

        if (posix_futex_owner(&file->lock, &owner) != 0)
            POSIX_PANIC("unexpected");

        if (owner == posix_self())
        {
            posix_futex_release(&file->lock);
            __unlockfile(file);
        }
        else
        {
            a_cas(&file->lock, value, 0);
        }
    }
}

void posix_exit(int status)
{
    posix_thread_t* thread;

    /* Release all files locked by this thread */
#if 1
    {
        for (FILE* file = *__ofl_lock(); file; file = file->next)
            _unlock_file_if_owner(file);

        __ofl_unlock();

        _unlock_file_if_owner(__stdin_used);
        _unlock_file_if_owner(__stdout_used);
        _unlock_file_if_owner(__stderr_used);
    }
#endif

    /* ATTN: ignored */
    (void)status;

    thread = posix_self();
    oe_assert(thread);

    /* ATTN: handle main thread exits */
    if (!thread->fn)
    {
        posix_printf("posix_exit() called from main thread\n");
        oe_abort();
    }

    /* Clear ctid: */
    posix_futex_acquire(thread->ctid);
    a_swap(thread->ctid, 0);
    posix_futex_release(thread->ctid);

    /* Wake the joiner */
    posix_futex_acquire((volatile int*)thread->ctid);
    posix_futex_wake((int*)thread->ctid, FUTEX_WAKE, 1);
    posix_futex_release((volatile int*)thread->ctid);

    /* Hack attempt to release joiner */
#if 1
    struct pthread* td = thread->td;
    ACQUIRE_FUTEX(&td->detach_state);
    int state = a_cas(&td->detach_state, DT_JOINABLE, DT_EXITING);
    (void)state;
    __wake(&td->detach_state, 1, 1);
    RELEASE_FUTEX(&td->detach_state);
#endif


    /* Jump back to posix_run_thread_ecall() */
    longjmp(thread->jmpbuf, 1);
}

void posix_force_exit(int status)
{
    posix_thread_t* thread;

    /* ATTN: ignored */
    (void)status;

    posix_printf("posix_force_exit()\n");

    thread = posix_self();
    oe_assert(thread);

    /* ATTN: handle main thread exits */
    if (!thread->fn)
    {
        posix_printf("posix_exit() called from main thread\n");
        oe_abort();
    }

#if 1
    /* Clear ctid: */
    posix_futex_acquire(thread->ctid);
    a_swap(thread->ctid, 0);
    posix_futex_release(thread->ctid);
#endif

    /* Wake the joiner */
    posix_futex_acquire((volatile int*)thread->ctid);
    posix_futex_wake((int*)thread->ctid, FUTEX_WAKE, 1);
    posix_futex_release((volatile int*)thread->ctid);

    /* Hack attempt to release joiner */
#if 1
    struct pthread* td = thread->td;
    ACQUIRE_FUTEX(&td->detach_state);
    int state = a_cas(&td->detach_state, DT_JOINABLE, DT_EXITING);
    (void)state;
    __wake(&td->detach_state, 1, 1);
    RELEASE_FUTEX(&td->detach_state);
#endif

    /* Jump back to posix_run_thread_ecall() */
    longjmp(thread->jmpbuf, 1);
}

long posix_get_robust_list(
    int pid,
    struct posix_robust_list_head** head_ptr,
    size_t* len_ptr)
{
    posix_thread_t* self = posix_self();

    if (pid != 0 || !(self = posix_self()))
        return -EINVAL;

    if (head_ptr)
        *head_ptr = self->robust_list_head;

    if (len_ptr)
        *len_ptr = self->robust_list_len;

    return 0;
}

long posix_set_robust_list(struct posix_robust_list_head* head, size_t len)
{
    posix_printf("head=%p\n", head);
    posix_printf("len=%zu\n", len);

    posix_thread_t* self = posix_self();

    if (!(self = posix_self()))
        return -EINVAL;

    self->robust_list_head = head;
    self->robust_list_len = len;

    return 0;
}

int posix_tkill(int tid, int sig)
{
    int retval;

    if (posix_tkill_ocall(&retval, tid, sig) != OE_OK)
        return -ENOSYS;

    posix_dispatch_signal();
    return retval;
}

void posix_noop(void)
{
    posix_noop_ocall();
}

void posix_abort(void)
{
    oe_abort();
}
