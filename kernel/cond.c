#include <errno.h>
#include <string.h>
#include <assert.h>
#include <libos/tcall.h>
#include <libos/cond.h>
#include <libos/mutex.h>
#include <libos/strings.h>

int libos_cond_init(libos_cond_t* c)
{
    if (!c)
        return EINVAL;

    libos_memset(c, 0, sizeof(libos_cond_t));
    c->lock = 0;

    return 0;
}

int libos_cond_destroy(libos_cond_t* c)
{
    if (!c)
        return EINVAL;

    libos_spin_lock(&c->lock);

    /* Fail if queue is not empty */
    if (c->queue.front)
    {
        libos_spin_unlock(&c->lock);
        return EBUSY;
    }

    libos_spin_unlock(&c->lock);

    return 0;
}

int libos_cond_timedwait(
    libos_cond_t* c,
    libos_mutex_t* mutex,
    const struct timespec* timeout)
{
    libos_thread_t* self = libos_self();
    int ret = 0;

    if (!c || !mutex)
        return EINVAL;

    libos_spin_lock(&c->lock);
    {
        libos_thread_t* waiter = NULL;

        /* Add the self thread to the end of the wait queue */
        libos_thread_queue_push_back(&c->queue, self);

        /* Unlock this mutex and get the waiter at the front of the queue */
        if (__libos_mutex_unlock(mutex, &waiter) != 0)
        {
            libos_spin_unlock(&c->lock);
            return EBUSY;
        }

        for (;;)
        {
            libos_spin_unlock(&c->lock);
            {
                if (waiter)
                {
                    ret = (int)libos_tcall_wake_wait(
                        waiter->tid,
                        self->tid,
                        timeout);

                    waiter = NULL;
                }
                else
                {
                    ret = (int)libos_tcall_wait(self->tid, timeout);
                }
            }
            libos_spin_lock(&c->lock);

            /* If self is no longer in the queue, then it was selected */
            if (!libos_thread_queue_contains(&c->queue, self))
                break;

            if (ret != 0)
                break;
        }
    }
    libos_spin_unlock(&c->lock);
    libos_mutex_lock(mutex);

    return ret;
}

int libos_cond_wait(libos_cond_t* c, libos_mutex_t* mutex)
{
    return libos_cond_timedwait(c, mutex, NULL);
}

int libos_cond_signal(libos_cond_t* c)
{
    libos_thread_t* waiter;

    if (!c)
        return EINVAL;

    libos_spin_lock(&c->lock);
    waiter = libos_thread_queue_pop_front(&c->queue);
    libos_spin_unlock(&c->lock);

    if (!waiter)
        return 0;

    libos_tcall_wake(waiter->tid);
    return 0;
}

int libos_cond_broadcast(libos_cond_t* c, size_t n)
{
    libos_thread_queue_t waiters = {NULL, NULL};

    if (!c)
        return EINVAL;

    libos_spin_lock(&c->lock);
    {
        libos_thread_t* p;
        size_t i = 0;

        /* Select at most n waiters to be woken up */
        while (i < n && (p = libos_thread_queue_pop_front(&c->queue)))
        {
            libos_thread_queue_push_back(&waiters, p);
            i++;
        }
    }
    libos_spin_unlock(&c->lock);

    libos_thread_t* next = NULL;

    for (libos_thread_t* p = waiters.front; p; p = next)
    {
        next = p->next;
        libos_tcall_wake(p->tid);
    }

    return 0;
}

int libos_cond_requeue(
    libos_cond_t* c1,
    libos_cond_t* c2,
    size_t wake_count,
    size_t requeue_count)
{
    libos_thread_queue_t wakers = {NULL, NULL};
    libos_thread_queue_t requeues = {NULL, NULL};

    if (!c1 || !c2)
        return EINVAL;

    /* Form two queues: wakers and requeues */
    libos_spin_lock(&c1->lock);
    {
        /* Select threads to be awoken */
        for (size_t i = 0; i < wake_count; i++)
        {
            libos_thread_t* p;

            if (!(p = libos_thread_queue_pop_front(&c1->queue)))
                break;

            libos_thread_queue_push_back(&wakers, p);
        }

        /* Selector threads to be required */
        for (size_t i = 0; i < requeue_count; i++)
        {
            libos_thread_t* p;

            if (!(p = libos_thread_queue_pop_front(&c1->queue)))
                break;

            libos_thread_queue_push_back(&requeues, p);
        }
    }
    libos_spin_unlock(&c1->lock);

    /* Wake the threads in the wakers queue */
    {
        libos_thread_t* next = NULL;

        for (libos_thread_t* p = wakers.front; p; p = next)
        {
            next = p->next;
            libos_tcall_wake(p->tid);
        }
    }

    /* Requeue the threads in the requeues queue */
    libos_spin_lock(&c2->lock);
    {
        libos_thread_t* next = NULL;

        for (libos_thread_t* p = requeues.front; p; p = next)
        {
            next = p->next;
            libos_thread_queue_push_back(&c2->queue, p);
        }
    }
    libos_spin_unlock(&c2->lock);

    return 0;
}
