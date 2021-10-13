#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <myst/eraise.h>

#define MAX_THREADS 65535

typedef struct thread_entry
{
    pid_t tid;
    pthread_t thread;
} thread_entry_t;

static thread_entry_t _entries[MAX_THREADS];
static size_t _nentries;
static pthread_mutex_t _lock;

int myst_register_thread(void)
{
    int ret = 0;

    pthread_mutex_lock(&_lock);

    if (_nentries == MAX_THREADS)
        ERAISE(-EINVAL);

    thread_entry_t entry = {syscall(SYS_gettid), pthread_self()};
    _entries[_nentries++] = entry;

done:
    pthread_mutex_unlock(&_lock);

    assert(ret == 0);
    return ret;
}

int myst_unregister_thread(void)
{
    int ret = 0;

    pthread_mutex_lock(&_lock);

    if (_nentries == MAX_THREADS)
        ERAISE(-EINVAL);

    for (size_t i = 0; i < _nentries; i++)
    {
        thread_entry_t* entry = &_entries[i];

        if (pthread_equal(entry->thread, pthread_self()))
        {
            _entries[i] = _entries[_nentries - 1];
            _nentries--;
            goto done;
        }
    }

    ret = -ESRCH;

done:
    pthread_mutex_unlock(&_lock);

    assert(ret == 0);
    return ret;
}

int myst_kill_thread(pid_t tid, int sig)
{
    int ret = 0;

    pthread_mutex_lock(&_lock);

    if (_nentries == MAX_THREADS)
        ERAISE(-EINVAL);

    for (size_t i = 0; i < _nentries; i++)
    {
        thread_entry_t* entry = &_entries[i];

        if (entry->tid == tid)
        {
            pthread_kill(entry->thread, sig);
            goto done;
        }
    }

    ret = -ESRCH;

done:
    pthread_mutex_unlock(&_lock);

    return ret;
}
