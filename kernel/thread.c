#include <libos/syscall.h>
#include <libos/tcall.h>
#include <libos/eraise.h>
#include <libos/strings.h>
#include <libos/thread.h>
#include <libos/malloc.h>
#include <libos/eraise.h>
#include <libos/trace.h>
#include <libos/fsbase.h>
#include <libos/spinlock.h>
#include <libos/setjmp.h>
#include <pthread.h>

typedef struct pair
{
    const void* fsbase;
    libos_thread_t* thread;
}
pair_t;

#define MAX_THREADS 1024

static pair_t _threads[MAX_THREADS];
static size_t _nthreads = 0;
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

int libos_add_thread(libos_thread_t* thread)
{
    int ret = -1;
    const void* fsbase = libos_get_fs_base();

    libos_spin_lock(&_lock);

    for (size_t i = 0; i < _nthreads; i++)
    {
        if (_threads[i].fsbase == fsbase)
            goto done;
    }

    if (_nthreads == MAX_THREADS)
        goto done;

    _threads[_nthreads].fsbase = fsbase;
    _threads[_nthreads].thread = thread;
    _nthreads++;

    ret = 0;

done:
    libos_spin_unlock(&_lock);

    return ret;
}

libos_thread_t* libos_self(void)
{
    libos_thread_t* ret = NULL;
    const void* fsbase = libos_get_fs_base();

    libos_spin_lock(&_lock);

    for (size_t i = 0; i < _nthreads; i++)
    {
        if (_threads[i].fsbase == fsbase)
        {
            ret = _threads[i].thread;
            break;
        }
    }

    libos_spin_unlock(&_lock);

    return ret;
}

libos_thread_t* libos_remove_thread(void)
{
    libos_thread_t* ret = NULL;
    const void* fsbase = libos_get_fs_base();

    libos_spin_lock(&_lock);

    for (size_t i = 0; i < _nthreads; i++)
    {
        if (_threads[i].fsbase == fsbase)
        {
            ret = _threads[i].thread;
            _threads[i] = _threads[_nthreads - 1];
            _nthreads--;
            break;
        }
    }

    libos_spin_unlock(&_lock);

    return ret;
}

static bool _valid_newtls(const void* newtls)
{
    struct pthread
    {
        struct pthread *self;
    };

    struct pthread* pt = (struct pthread*)newtls;
    return pt && pt->self == pt;
}

/* The target calls this from the new thread */
static long _run(libos_thread_t* thread)
{
    long ret = 0;

    if (!thread || thread->magic != LIBOS_THREAD_MAGIC)
        ERAISE(-EINVAL);

    thread->original_fsbase = libos_get_fs_base();

    libos_set_fs_base(thread->newtls);

    if (libos_add_thread(thread) != 0)
    {
        ERAISE(-ENOMEM);
    }

    /* Jump back here from exit */
    if (libos_setjmp(&thread->jmpbuf) != 0)
    {
        /* restore the original fsbase */
        libos_set_fs_base(thread->original_fsbase);

        /* remove the thread from the map */
        libos_remove_thread();
    }
    else
    {
        (*thread->fn)(thread->arg);
        /* unreachable */
    }

done:

    if (thread)
        libos_free(thread);

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
    libos_thread_t* thread;

    if (!fn)
        ERAISE(-EINVAL);

    if (!_valid_newtls(newtls))
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
#ifdef ENABLE_HOST_THREADS
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
