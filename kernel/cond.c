// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <myst/cond.h>
#include <myst/mutex.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/tcall.h>

int myst_cond_init(myst_cond_t* c)
{
    if (!c)
        return -EINVAL;

    memset(c, 0, sizeof(myst_cond_t));
    c->lock = 0;

    return 0;
}

int myst_cond_destroy(myst_cond_t* c)
{
    if (!c)
        return -EINVAL;

    myst_spin_lock(&c->lock);

    /* Fail if queue is not empty */
    if (c->queue.front)
    {
        myst_spin_unlock(&c->lock);
        return -EBUSY;
    }

    myst_spin_unlock(&c->lock);

    return 0;
}

int myst_cond_timedwait(
    myst_cond_t* c,
    myst_mutex_t* mutex,
    const struct timespec* timeout)
{
    myst_thread_t* self = myst_thread_self();
    int ret = 0;

    assert(self != NULL);
    assert(self->magic == MYST_THREAD_MAGIC);

    if (!c || !mutex)
        return -EINVAL;

    myst_spin_lock(&c->lock);
    {
        myst_thread_t* waiter = NULL;

        /* Add the self thread to the end of the wait queue */
        myst_thread_queue_push_back(&c->queue, self);

        self->signal.waiting_on_event = true;
        if (c->queue.front != c->queue.back &&
            c->queue.front->status == MYST_ZOMBIE)
        {
            assert(0 && "Found zombie in conditional variable's waiting list");
        }

        /* Unlock this mutex and get the waiter at the front of the queue */
        if (__myst_mutex_unlock(mutex, &waiter) != 0)
        {
            myst_spin_unlock(&c->lock);
            return -EBUSY;
        }

        for (;;)
        {
            myst_spin_unlock(&c->lock);
            {
                if (waiter)
                {
                    ret = (int)myst_tcall_wake_wait(
                        waiter->event, self->event, timeout);

                    waiter = NULL;
                }
                else
                {
                    ret = (int)myst_tcall_wait(self->event, timeout);
                }
            }
            myst_spin_lock(&c->lock);

            /* If self is no longer in the queue, then it was selected by the
             * myst_signal_xyz() calls. Break out of the loop to unblock the
             * thread. If self is still in the queue, and ret=0, host-side might
             * have waken the thread prematurely, potentially doing so
             * maliciously. Stay in the loop to wait again.
             */
            if (!myst_thread_queue_contains(&c->queue, self))
                break;

            /* Remove self from the queue on error returns such as ETIMEOUT, and
             * break out of the loop to report error to the calling function.
             * The calling function should check/process error condition before
             * continuing execution. */
            if (ret < 0)
            {
                myst_thread_queue_remove_thread(&c->queue, self);
                break;
            }
        }
        self->signal.waiting_on_event = false;
    }

    myst_spin_unlock(&c->lock);
    myst_mutex_lock(mutex);

    return ret;
}

int myst_cond_wait(myst_cond_t* c, myst_mutex_t* mutex)
{
    return myst_cond_timedwait(c, mutex, NULL);
}

int myst_cond_signal_thread(myst_cond_t* c, myst_thread_t* thread)
{
    int index = -1;

    if (!c)
        return -EINVAL;

    myst_spin_lock(&c->lock);
    index = myst_thread_queue_remove_thread(&c->queue, thread);
    myst_spin_unlock(&c->lock);

    if (index >= 0)
        myst_tcall_wake(thread->event);

    return 0;
}

int myst_cond_signal(myst_cond_t* c)
{
    myst_thread_t* waiter;

    if (!c)
        return -EINVAL;

    myst_spin_lock(&c->lock);
    do
    {
        waiter = myst_thread_queue_pop_front(&c->queue);
    } while (waiter && waiter->status == MYST_ZOMBIE);
    myst_spin_unlock(&c->lock);

    if (!waiter)
        return 0;

    waiter->qnext = NULL;
    myst_tcall_wake(waiter->event);
    return 0;
}

int myst_cond_broadcast(myst_cond_t* c, size_t n)
{
    size_t num_awoken = 0;
    myst_thread_queue_t waiters = {NULL, NULL};

    if (!c)
        return -EINVAL;

    myst_spin_lock(&c->lock);
    {
        myst_thread_t* p;
        size_t i = 0;

        /* Select at most n waiters to be woken up */
        while (i < n && (p = myst_thread_queue_pop_front(&c->queue)))
        {
            myst_thread_queue_push_back(&waiters, p);
            i++;
        }
    }
    myst_spin_unlock(&c->lock);

    myst_thread_t* next = NULL;

    for (myst_thread_t* p = waiters.front; p; p = next)
    {
        next = p->qnext;
        myst_tcall_wake(p->event);
        num_awoken++;
    }

    return num_awoken;
}

int myst_cond_requeue(
    myst_cond_t* c1,
    myst_cond_t* c2,
    size_t wake_count,
    size_t requeue_count)
{
    myst_thread_queue_t wakers = {NULL, NULL};
    myst_thread_queue_t requeues = {NULL, NULL};

    if (!c1 || !c2)
        return -EINVAL;

    /* Form two queues: wakers and requeues */
    myst_spin_lock(&c1->lock);
    {
        /* Select threads to be awoken */
        for (size_t i = 0; i < wake_count; i++)
        {
            myst_thread_t* p;

            if (!(p = myst_thread_queue_pop_front(&c1->queue)))
                break;

            myst_thread_queue_push_back(&wakers, p);
        }

        /* Selector threads to be required */
        for (size_t i = 0; i < requeue_count; i++)
        {
            myst_thread_t* p;

            if (!(p = myst_thread_queue_pop_front(&c1->queue)))
                break;

            myst_thread_queue_push_back(&requeues, p);
        }
    }
    myst_spin_unlock(&c1->lock);

    /* Wake the threads in the wakers queue */
    {
        myst_thread_t* next = NULL;

        for (myst_thread_t* p = wakers.front; p; p = next)
        {
            next = p->qnext;
            myst_tcall_wake(p->event);
        }
    }

    /* Requeue the threads in the requeues queue */
    myst_spin_lock(&c2->lock);
    {
        myst_thread_t* next = NULL;

        for (myst_thread_t* p = requeues.front; p; p = next)
        {
            next = p->qnext;
            p->signal.waiting_on_event = true;
            myst_thread_queue_push_back(&c2->queue, p);
        }
    }
    myst_spin_unlock(&c2->lock);

    return 0;
}
