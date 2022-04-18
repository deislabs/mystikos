// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <myst/mutex.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/thread.h>

int myst_mutex_init(myst_mutex_t* m)
{
    if (!m)
        return -EINVAL;

    memset(m, 0, sizeof(myst_mutex_t));
    m->lock = 0;

    return 0;
}

/* Caller manages the spinlock */
int __myst_mutex_trylock(myst_mutex_t* m, myst_thread_t* self)
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
            myst_thread_queue_pop_front(&m->queue);

            /* Obtain the mutex */
            m->owner = self;
            m->refs = 1;
            return 0;
        }
    }

    /* the mutex is already locked by another thread */
    return -EBUSY;
}

static int _mutex_lock(myst_mutex_t* mutex)
{
    myst_mutex_t* m = (myst_mutex_t*)mutex;
    myst_thread_t* self = myst_thread_self();

    if (!m)
        return -EINVAL;

    /* Loop until SELF obtains mutex */
    for (;;)
    {
        long r;

        myst_spin_lock(&m->lock);
        {
            /* Attempt to acquire lock */
            if (__myst_mutex_trylock(m, self) == 0)
            {
                myst_spin_unlock(&m->lock);
                return 0;
            }

            /* If the waiters queue does not contain this thread */
            if (!myst_thread_queue_contains(&m->queue, self))
            {
                /* Insert thread at back of waiters queue */
                myst_thread_queue_push_back(&m->queue, self);
            }

            /* check whether any signals were raised on this thread */
            if (myst_signal_has_active_signals(self))
            {
                myst_thread_queue_remove_thread(&m->queue, self);
                myst_spin_unlock(&m->lock);
                return -EINTR;
            }
        }
        myst_spin_unlock(&m->lock);

        /* Ask host to wait for an event on this thread */
        self->signal.waiting_on_event = true;
        if ((r = myst_tcall_wait(self->event, NULL)) != 0)
            myst_panic("myst_tcall_wait(): %ld: %d", r, *(int*)self->event);
        self->signal.waiting_on_event = false;
    }

    /* Unreachable! */
}

int myst_mutex_trylock(myst_mutex_t* mutex)
{
    myst_mutex_t* m = (myst_mutex_t*)mutex;
    myst_thread_t* self = myst_thread_self();

    if (!m)
        return -EINVAL;

    myst_spin_lock(&m->lock);
    {
        /* Attempt to acquire lock */
        if (__myst_mutex_trylock(m, self) == 0)
        {
            myst_spin_unlock(&m->lock);
            return 0;
        }
    }
    myst_spin_unlock(&m->lock);

    return -EBUSY;
}

int __myst_mutex_unlock(myst_mutex_t* mutex, myst_thread_t** waiter)
{
    int ret = 0;
    myst_mutex_t* m = (myst_mutex_t*)mutex;
    myst_thread_t* self = myst_thread_self();

    myst_spin_lock(&m->lock);
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
        }
        else
        {
            /* the caller does not own the mutex */
            ret = -EPERM;
        }
    }
    myst_spin_unlock(&m->lock);

    return ret;
}

int myst_mutex_unlock(myst_mutex_t* m)
{
    myst_thread_t* waiter = NULL;

    if (!m)
        return -EINVAL;

    if (__myst_mutex_unlock(m, &waiter) != 0)
        return -EPERM;

    if (waiter)
    {
        /* Ask host to wake up this thread */
        myst_tcall_wake(waiter->event);
    }

    return 0;
}

int myst_mutex_destroy(myst_mutex_t* mutex)
{
    int ret = 0;
    myst_mutex_t* m = (myst_mutex_t*)mutex;

    if (!m)
        return -EINVAL;

    myst_spin_lock(&m->lock);
    {
        if (myst_thread_queue_empty(&m->queue))
        {
            memset(m, 0, sizeof(myst_mutex_t));
        }
        else
        {
            ret = -EBUSY;
        }
    }
    myst_spin_unlock(&m->lock);

    return ret;
}

myst_thread_t* myst_mutex_owner(myst_mutex_t* m)
{
    myst_thread_t* owner;

    if (!m)
        return NULL;

    myst_spin_lock(&m->lock);
    owner = m->owner;
    myst_spin_unlock(&m->lock);

    return owner;
}

int myst_mutex_lock(myst_mutex_t* mutex)
{
    int ret;
    myst_thread_t* self = myst_thread_self();

    /* repeat as long as there is an -EINTR error */
    while ((ret = _mutex_lock(mutex)) == -EINTR)
    {
        /* check for signals */
        myst_signal_process(self);
    }

    return ret;
}
