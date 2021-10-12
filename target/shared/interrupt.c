#include <assert.h>
#include <pthread.h>
#include <sys/signal.h>
#include <sys/syscall.h>

#include <myst/eraise.h>
#include <myst/interrupt.h>
#include <myst/tcall.h>

#define MAX_THREADS 65536

typedef struct thread_entry
{
    /* the thread identifier */
    pid_t tid;

    /* incremented by myst_tcall_interrupt_thread() */
    size_t interruptions;

    /* nesting of thread (0 or 1) */
    size_t nesting;
} thread_entry_t;

static thread_entry_t _threads[MAX_THREADS];
static size_t _nthreads;
static pthread_mutex_t _lock;

static ssize_t _find_thread_no_lock(pid_t tid)
{
    for (size_t i = 0; i < _nthreads; i++)
    {
        if (_threads[i].tid == tid)
            return i;
    }

    /* not found */
    return -ESRCH;
}

int myst_register_interruptable_thread(void)
{
    int ret = 0;
    ssize_t index;
    pid_t tid;

    pthread_mutex_lock(&_lock);

    if ((tid = syscall(SYS_gettid)) < 0)
        ERAISE(-ENOSYS);

    /* if thread has already been interrupted */
    if ((index = _find_thread_no_lock(tid)) >= 0)
    {
        if (_threads[index].interruptions > 0)
        {
            if (--_threads[index].interruptions == 0)
            {
                _threads[index] = _threads[_nthreads - 1];
                _nthreads--;
            }

            ERAISE(-EINTR);
        }

        assert(0);
    }

    /* if no more space in the threads array */
    if (_nthreads == MAX_THREADS)
    {
        assert(0);
        ERAISE(-ENOSYS);
    }

    _threads[_nthreads].tid = tid;
    _threads[_nthreads].interruptions = 0;
    _threads[_nthreads].nesting = 1;
    _nthreads++;

done:
    pthread_mutex_unlock(&_lock);

    return ret;
}

int myst_unregister_interruptable_thread(void)
{
    int ret = 0;
    ssize_t index;
    pid_t tid;

    pthread_mutex_lock(&_lock);

    if ((tid = syscall(SYS_gettid)) < 0)
        ERAISE(-ENOSYS);

    index = _find_thread_no_lock(tid);
    assert(index >= 0);
    ECHECK(index);

    _threads[_nthreads].nesting = 0;

    if (_threads[index].interruptions == 0)
    {
        _threads[index] = _threads[_nthreads - 1];
        _nthreads--;
    }

done:
    pthread_mutex_unlock(&_lock);

    return ret;
}

long myst_tcall_interrupt_thread(pid_t tid)
{
    long ret = 0;
    ssize_t index;

    pthread_mutex_lock(&_lock);

    if (tid <= 0)
        ERAISE(-EINVAL);

    if ((index = _find_thread_no_lock(tid)) >= 0)
    {
        _threads[index].interruptions++;

        if (_threads[index].nesting)
        {
            if (syscall(SYS_tkill, tid, SIGUSR2) != 0)
                ERAISE(-errno);
        }
    }
    else
    {
        _threads[_nthreads].tid = tid;
        _threads[_nthreads].interruptions = 1;
        _threads[_nthreads].nesting = 0;
        _nthreads++;
    }

done:
    pthread_mutex_unlock(&_lock);

    return ret;
}
