#include <libos/assert.h>
#include <libos/atexit.h>
#include <libos/atomic.h>
#include <libos/eraise.h>
#include <libos/fsbase.h>
#include <libos/futex.h>
#include <libos/malloc.h>
#include <libos/setjmp.h>
#include <libos/spinlock.h>
#include <libos/strings.h>
#include <libos/syscall.h>
#include <libos/tcall.h>
#include <libos/thread.h>
#include <libos/trace.h>
#include <pthread.h>

libos_thread_t* __libos_main_thread;

static libos_thread_t* _threads;
static size_t _nthreads;
static libos_thread_t* _zombies;
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

size_t libos_get_num_active_threads(void)
{
    size_t n;

    libos_spin_lock(&_lock);
    n = _nthreads;
    libos_spin_unlock(&_lock);

    return n;
}

#if 0
static size_t _count_threads_no_lock(void)
{
    size_t n = 0;

    for (libos_thread_t* p = _threads; p; p = p->next)
        n++;

    return n;
}
#endif

static int _add_thread(libos_thread_t* thread)
{
    int ret = 0;

    libos_spin_lock(&_lock);

    for (libos_thread_t* p = _threads; p; p = p->next)
    {
        if (p == thread)
        {
            ret = -1;
            goto done;
        }
    }

    thread->next = _threads;
    _threads = thread;
    _nthreads++;

done:
    libos_spin_unlock(&_lock);

    return ret;
}

static int _remove_thread(libos_thread_t* thread)
{
    int ret = -1;

    libos_spin_lock(&_lock);
    {
        libos_thread_t* prev = NULL;

        for (libos_thread_t* p = _threads; p; p = p->next)
        {
            if (p == thread)
            {
                if (prev)
                    prev->next = p->next;
                else
                    _threads = p->next;

                _nthreads--;

                ret = 0;
                break;
            }

            prev = p;
        }
    }
    libos_spin_unlock(&_lock);

    return ret;
}

static void _free_zombies(void* arg)
{
    libos_thread_t* p;

    (void)arg;

    for (p = _zombies; p;)
    {
        libos_thread_t* next = p->next;

        libos_memset(p, 0xdd, sizeof(libos_thread_t));
        libos_free(p);

        p = next;
    }

    _zombies = NULL;
}

void libos_release_thread(libos_thread_t* thread)
{
    libos_spin_lock(&_lock);
    {
        static bool _initialized;

        if (!_initialized)
        {
            libos_atexit(_free_zombies, NULL);
            _initialized = true;
        }

        thread->next = _zombies;
        _zombies = thread;
    }
    libos_spin_unlock(&_lock);
}

bool libos_valid_pthread(const void* pthread)
{
    return pthread && ((const struct pthread*)pthread)->self == pthread;
}

static bool _valid_thread(const libos_thread_t* thread)
{
    return thread && thread->magic == LIBOS_THREAD_MAGIC;
}

libos_thread_t* libos_self(void)
{
    const struct pthread* pthread = libos_get_fs_base();

    if (!libos_valid_pthread(pthread))
        libos_panic("invalid pthread");

    return (libos_thread_t*)pthread->unused;
}

static void _call_thread_fn(void)
{
    libos_thread_t* thread = libos_self();

    if (!thread)
        libos_panic("%s()", __FUNCTION__);

    thread->fn(thread->arg);
}

/* The target calls this from the new thread */
static long _run(libos_thread_t* thread, pid_t tid, uint64_t event)
{
    struct pthread* pthread;

    if (!_valid_thread(thread))
        return -EINVAL;

    if (!libos_valid_pthread(pthread = thread->newtls))
        return -EINVAL;

    thread->tid = tid;
    thread->event = event;
    thread->original_fsbase = libos_get_fs_base();

    /* link pthread to libos_thread */
    pthread->unused = (uint64_t)thread;

    /* add the thread to the active list */
    if (_add_thread(thread) != 0)
        libos_panic("_add_thread() failed");

    libos_set_fs_base(pthread);

    /* Set the TID for this thread (sets the pthread tid field */
    libos_atomic_exchange(thread->ptid, tid);

    /* Jump back here from exit */
    if (libos_setjmp(&thread->jmpbuf) != 0)
    {
        libos_assert(libos_gettid() != -1);

        libos_atomic_exchange(thread->ctid, 0);

        /* Wake the thread that is waiting on thread->ctid */
        const int futex_op = FUTEX_WAKE | FUTEX_PRIVATE;
        libos_syscall_futex(thread->ctid, futex_op, 1, 0, NULL, 0);

        if (_remove_thread(thread) != 0)
        {
            libos_panic("_remove_thread() failed");
        }

        /* restore the original fsbase */
        libos_set_fs_base(thread->original_fsbase);

        /* free the thread */
        libos_assert(pthread->unused == (uint64_t)thread);
        pthread->unused = 0;

        libos_release_thread(thread);
    }
    else
    {
#ifdef LIBOS_USE_THREAD_STACK
        libos_jmp_buf_t env = thread->jmpbuf;

        env.rip = (uint64_t)_call_thread_fn;
        env.rsp = (uint64_t)thread->child_stack;
        env.rbp = (uint64_t)thread->child_stack;
        libos_jump(&env);
#else
        (*thread->fn)(thread->arg);
        (void)_call_thread_fn;
#endif
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
    libos_thread_t* thread;

    if (!fn)
        ERAISE(-EINVAL);

    if (!libos_valid_pthread(newtls))
        ERAISE(-EINVAL);

    /* Create and initialize the thread struct */
    {
        if (!(thread = libos_calloc(1, sizeof(libos_thread_t))))
            ERAISE(-ENOMEM);

        thread->magic = LIBOS_THREAD_MAGIC;
        thread->fn = fn;
        thread->child_stack = child_stack;
        thread->flags = flags;
        thread->arg = arg;
        thread->ptid = ptid;
        thread->newtls = newtls;
        thread->ctid = ctid;
        thread->run = _run;
    }

    cookie = (uint64_t)thread;

    if (libos_tcall_create_host_thread(cookie) != 0)
        ERAISE(-EINVAL);

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
#ifdef LIBOS_ENABLE_HOST_THREADS
    return _syscall_clone(fn, child_stack, flags, arg, ptid, newtls, ctid);
#else
    (void)fn;
    (void)child_stack;
    (void)flags;
    (void)arg;
    (void)ptid;
    (void)newtls;
    (void)ctid;
    (void)_syscall_clone;
    return 0;
#endif
}

pid_t libos_gettid(void)
{
    libos_thread_t* thread;

    if (!(thread = libos_self()))
    {
        // libos_panic("unexpected");
        return -1;
    }

    return thread->tid;
}
