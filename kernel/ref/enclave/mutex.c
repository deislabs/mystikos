#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include "posix_mutex.h"
#include "posix_thread.h"
#include "posix_ocalls.h"
#include "posix_ocall_structs.h"
#include "posix_signal.h"
#include "posix_io.h"
#include "posix_panic.h"
/* */
#include "posix_warnings.h"

int posix_mutex_init(posix_mutex_t* m)
{
    int ret = -1;

    if (!m)
        return EINVAL;

    memset(m, 0, sizeof(posix_mutex_t));
    m->lock = 0;

    ret = 0;

    return ret;
}

/* Caller manages the spinlock */
int __posix_mutex_trylock(posix_mutex_t* m, posix_thread_t* self)
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
            posix_thread_queue_pop_front(&m->queue);

            /* Obtain the mutex */
            m->owner = self;
            m->refs = 1;
            return 0;
        }
    }

    return -1;
}

int posix_mutex_lock(posix_mutex_t* mutex)
{
    posix_mutex_t* m = (posix_mutex_t*)mutex;
    posix_thread_t* self = posix_self();

    if (!m)
        return EINVAL;

    /* Loop until SELF obtains mutex */
    for (;;)
    {
        int retval;

        posix_spin_lock(&m->lock);
        {
            /* Attempt to acquire lock */
            if (__posix_mutex_trylock(m, self) == 0)
            {
                posix_spin_unlock(&m->lock);
                return 0;
            }

            /* If the waiters queue does not contain this thread */
            if (!posix_thread_queue_contains(&m->queue, self))
            {
                /* Insert thread at back of waiters queue */
                posix_thread_queue_push_back(&m->queue, self);
            }
        }
        posix_spin_unlock(&m->lock);

        /* Ask host to wait for an event on this thread */
        if (posix_wait_ocall(&retval, &self->shared_block->futex, NULL) != OE_OK)
        {
            POSIX_PANIC("posix_wait_ocall()");
        }
        posix_dispatch_signal();
    }

    /* Unreachable! */
}

int posix_mutex_trylock(posix_mutex_t* mutex)
{
    posix_mutex_t* m = (posix_mutex_t*)mutex;
    posix_thread_t* self = posix_self();

    if (!m)
        return EINVAL;

    posix_spin_lock(&m->lock);
    {
        /* Attempt to acquire lock */
        if (__posix_mutex_trylock(m, self) == 0)
        {
            posix_spin_unlock(&m->lock);
            return 0;
        }
    }
    posix_spin_unlock(&m->lock);

    return EBUSY;
}

int __posix_mutex_unlock(posix_mutex_t* mutex, posix_thread_t** waiter)
{
    posix_mutex_t* m = (posix_mutex_t*)mutex;
    posix_thread_t* self = posix_self();
    int ret = -1;

    posix_spin_lock(&m->lock);
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
    posix_spin_unlock(&m->lock);

    return ret;
}

int posix_mutex_unlock(posix_mutex_t* m)
{
    posix_thread_t* waiter = NULL;

    if (!m)
        return EINVAL;

    if (__posix_mutex_unlock(m, &waiter) != 0)
        return EPERM;

    if (waiter)
    {
        /* Ask host to wake up this thread */
        posix_wake_ocall(&waiter->shared_block->futex);
    }

    return 0;
}

int posix_mutex_destroy(posix_mutex_t* mutex)
{
    posix_mutex_t* m = (posix_mutex_t*)mutex;

    if (!m)
        return EINVAL;

    int ret = EBUSY;

    posix_spin_lock(&m->lock);
    {
        if (posix_thread_queue_empty(&m->queue))
        {
            memset(m, 0, sizeof(posix_mutex_t));
            ret = 0;
        }
    }
    posix_spin_unlock(&m->lock);

    return ret;
}

posix_thread_t* posix_mutex_owner(posix_mutex_t* m)
{
    posix_thread_t* owner;

    if (!m)
        return NULL;

    posix_spin_lock(&m->lock);
    owner = m->owner;
    posix_spin_unlock(&m->lock);

    return owner;
}
