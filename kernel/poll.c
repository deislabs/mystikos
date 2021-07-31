// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/fdops.h>
#include <myst/fdtable.h>
#include <myst/signal.h>
#include <myst/sockdev.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/time.h>

long _poll_kernel(struct pollfd* fds, nfds_t nfds)
{
    long ret = 0;
    myst_fdtable_t* fdtable;
    long total = 0;

    if (!(fdtable = myst_fdtable_current()))
        ERAISE(-ENOSYS);

    for (nfds_t i = 0; i < nfds; i++)
    {
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;
        void* object;
        int events;

        fds[i].revents = 0;

        /* get the device for this file descriptor */
        int res = myst_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object);
        if (res == -ENOENT)
            continue;
        ECHECK(res);

        if ((events = (*fdops->fd_get_events)(fdops, object)) >= 0)
        {
            /* Only report events requested or POLLERR, POLLHUP and POLLNVAL*/
            if (events =
                    events & ((fds[i].events) | (POLLERR | POLLHUP | POLLNVAL)))
            {
                fds[i].revents = events;
                total++;
            }
        }
        else if (events != -ENOTSUP)
        {
            continue;
        }
    }

    ret = total;

done:
    return ret;
}

static long _syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret = 0;
    myst_fdtable_t* fdtable;
    struct pollfd* tfds = NULL; /* target file descriptors */
    struct pollfd* kfds = NULL; /* kernel file descriptors */
    nfds_t tnfds = 0;           /* number of target file descriptors */
    nfds_t knfds = 0;           /* number of kernel file descriptors */
    size_t* tindices = NULL;    /* target indices */
    size_t* kindices = NULL;    /* kernel indices */
    long tevents = 0;           /* the number of target events */
    long kevents = 0;           /* the number of kernel events */
    long nvalevents = 0;        /* the number of POLLNVAL events */
    static myst_spinlock_t _lock;
    bool locked = false;
    long has_signals = 0;
    int original_timeout = timeout;
    struct timespec start;
    struct timespec end;
    long lapsed = 0;

    /* special case: if nfds is zero */
    if (nfds == 0)
    {
        long r;
        long params[6] = {(long)NULL, nfds, timeout};
        ECHECK((r = myst_tcall(SYS_poll, params)));
        ret = r;
        goto done;
    }

    if (!fds && nfds)
        ERAISE(-EFAULT);

    if (!(fdtable = myst_fdtable_current()))
        ERAISE(-ENOSYS);

    if (!(tfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(kfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(tindices = calloc(nfds, sizeof(size_t))))
        ERAISE(-ENOMEM);

    if (!(kindices = calloc(nfds, sizeof(size_t))))
        ERAISE(-ENOMEM);

    myst_spin_lock(&_lock);
    locked = true;

    /* Split fds[] into two arrays: tfds[] (target) and kfds[] (kernel) */
    for (nfds_t i = 0; i < nfds; i++)
    {
        int tfd;
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;
        void* object;

        /* get the device for this file descriptor */
        int res = (myst_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object));

        if (res == -ENOENT)
            continue;
        else if (res == -EBADF)
        {
            /* closed/invalid fd gets POLLNVAL */
            fds[i].revents = POLLNVAL;
            nvalevents++;
            continue;
        }
        ECHECK(res);

        /* get the target fd for this object (or -ENOTSUP) */
        if ((tfd = (*fdops->fd_target_fd)(fdops, object)) >= 0)
        {
            tfds[tnfds].events = fds[i].events;
            tfds[tnfds].fd = tfd;
            tindices[tnfds] = i;
            tnfds++;
        }
        else if (tfd == -ENOTSUP)
        {
            kfds[knfds].events = fds[i].events;
            kfds[knfds].fd = fds[i].fd;
            kindices[knfds] = i;
            knfds++;
        }
        else
        {
            continue;
        }
    }

    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &start);
    if ((original_timeout > 500) || (original_timeout < 0))
        timeout = 500;
    else
        timeout = original_timeout;

    while (1)
    {
        /* pre-poll for kernel events */
        ECHECK((kevents = _poll_kernel(kfds, knfds)));
        /* report kernel events or POLLNVAL events immediately */
        if (kevents || nvalevents)
            break;

        myst_spin_unlock(&_lock);
        locked = false;

        /* poll for target events */
        if (tnfds && tfds)
        {
            tevents = myst_tcall_poll(tfds, tnfds, timeout);
        }
        else
        {
            tevents = myst_tcall_poll(NULL, tnfds, timeout);
        }

        ECHECK(tevents);
        if (tevents > 0)
            break;

        has_signals = myst_signal_has_active_signals(myst_thread_self());
        if (has_signals)
        {
            ret = -EINTR;
            goto done;
        }

        if (original_timeout == 0)
            break;

        // work out if we have timed out yet
        myst_syscall_clock_gettime(CLOCK_MONOTONIC, &end);

        lapsed += ((end.tv_sec - start.tv_sec) * 1000000000 +
                   (end.tv_nsec - start.tv_nsec)) /
                  1000000;

        if ((original_timeout > 0) && ((original_timeout - lapsed) <= 0))
            break;

        if (original_timeout > 0)
            timeout = original_timeout - lapsed;
        else
            timeout = 500;

        myst_spin_lock(&_lock);
        locked = true;
    }

    ret = kevents + tevents + nvalevents;

    /* update fds[] with the target events */
    for (nfds_t i = 0; i < tnfds; i++)
        fds[tindices[i]].revents = tfds[i].revents;

    /* update fds[] with the kernel events */
    for (nfds_t i = 0; i < knfds; i++)
        fds[kindices[i]].revents = kfds[i].revents;

done:

    if (locked)
        myst_spin_unlock(&_lock);

    if (tfds)
        free(tfds);

    if (kfds)
        free(kfds);

    if (tindices)
        free(tindices);

    if (kindices)
        free(kindices);

    return ret;
}

long myst_syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret = 0;
    long r;

    ECHECK((r = _syscall_poll(fds, nfds, timeout)));

    if (r == 0 && timeout < 0)
    {
        // Some applications hang when this function does not return
        // periodically, even when there are no file-descriptor events.
        // To avoid this hang, we return EINTR to fake interruption of poll()
        // by a signal. Any robust application must be prepared to handle
        // EINTR.
        ret = -EINTR;
    }
    else
        ret = r;

done:
    return ret;
}
