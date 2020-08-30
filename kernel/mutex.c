#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <libos/mutex.h>
#include <libos/thread.h>
#include <libos/tcall.h>
#include <libos/strings.h>

int libos_mutex_init(libos_mutex_t* m)
{
    int ret = -1;

    if (!m)
        return EINVAL;

    libos_memset(m, 0, sizeof(libos_mutex_t));
    m->lock = 0;

    ret = 0;

    return ret;
}

/* Caller manages the spinlock */
int __libos_mutex_trylock(libos_mutex_t* m, libos_thread_t* self)
{
    /* If this thread has already locked the mutex */
    if (m->owner == self)
    {
        /* Increase the reference count */
        m->refs++;
        return 0;
    }

    /* If no thread has locked this mutex yet */
    if (m->owner == NULL)
    {
        /* If the waiters queue is empty */
        if (m->queue.front == NULL)
        {
            /* Obtain the mutex */
            m->owner = self;
            m->refs = 1;
            return 0;
        }

        /* If this thread is at the front of the waiters queue */
        if (m->queue.front == self)
        {
            /* Remove this thread from front of the waiters queue */
            libos_thread_queue_pop_front(&m->queue);

            /* Obtain the mutex */
            m->owner = self;
            m->refs = 1;
            return 0;
        }
    }

    return -1;
}

int libos_mutex_lock(libos_mutex_t* mutex)
{
    libos_mutex_t* m = (libos_mutex_t*)mutex;
    libos_thread_t* self = libos_self();

    if (!m)
        return EINVAL;

    /* Loop until SELF obtains mutex */
    for (;;)
    {
        libos_spin_lock(&m->lock);
        {
            /* Attempt to acquire lock */
            if (__libos_mutex_trylock(m, self) == 0)
            {
                libos_spin_unlock(&m->lock);
                return 0;
            }

            /* If the waiters queue does not contain this thread */
            if (!libos_thread_queue_contains(&m->queue, self))
            {
                /* Insert thread at back of waiters queue */
                libos_thread_queue_push_back(&m->queue, self);
            }
        }
        libos_spin_unlock(&m->lock);

        /* Ask host to wait for an event on this thread */
        if (libos_tcall_wait(self->event, NULL) != 0)
            libos_panic("unexpected");
    }

    /* Unreachable! */
}

int libos_mutex_trylock(libos_mutex_t* mutex)
{
    libos_mutex_t* m = (libos_mutex_t*)mutex;
    libos_thread_t* self = libos_self();

    if (!m)
        return EINVAL;

    libos_spin_lock(&m->lock);
    {
        /* Attempt to acquire lock */
        if (__libos_mutex_trylock(m, self) == 0)
        {
            libos_spin_unlock(&m->lock);
            return 0;
        }
    }
    libos_spin_unlock(&m->lock);

    return EBUSY;
}

int __libos_mutex_unlock(libos_mutex_t* mutex, libos_thread_t** waiter)
{
    libos_mutex_t* m = (libos_mutex_t*)mutex;
    libos_thread_t* self = libos_self();
    int ret = -1;

    libos_spin_lock(&m->lock);
    {
        /* If this thread has the mutex locked */
        if (m->owner == self)
        {
            /* If decreasing the reference count causes it to become zero */
            if (--m->refs == 0)
            {
                /* Thread no longer has this mutex locked */
                m->owner = NULL;

                /* Set waiter to the next thread on the queue (maybe none) */
                *waiter = m->queue.front;
            }

            ret = 0;
        }
    }
    libos_spin_unlock(&m->lock);

    return ret;
}

int libos_mutex_unlock(libos_mutex_t* m)
{
    libos_thread_t* waiter = NULL;

    if (!m)
        return EINVAL;

    if (__libos_mutex_unlock(m, &waiter) != 0)
        return EPERM;

    if (waiter)
    {
        /* Ask host to wake up this thread */
        libos_tcall_wake(waiter->event);
    }

    return 0;
}

int libos_mutex_destroy(libos_mutex_t* mutex)
{
    libos_mutex_t* m = (libos_mutex_t*)mutex;

    if (!m)
        return EINVAL;

    int ret = EBUSY;

    libos_spin_lock(&m->lock);
    {
        if (libos_thread_queue_empty(&m->queue))
        {
            libos_memset(m, 0, sizeof(libos_mutex_t));
            ret = 0;
        }
    }
    libos_spin_unlock(&m->lock);

    return ret;
}

libos_thread_t* libos_mutex_owner(libos_mutex_t* m)
{
    libos_thread_t* owner;

    if (!m)
        return NULL;

    libos_spin_lock(&m->lock);
    owner = m->owner;
    libos_spin_unlock(&m->lock);

    return owner;
}
