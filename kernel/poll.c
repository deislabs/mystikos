// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>

#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/fdops.h>
#include <myst/fdtable.h>
#include <myst/mmanutils.h>
#include <myst/signal.h>
#include <myst/sockdev.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/time.h>
#include <myst/times.h>

static long _syscall_poll(
    struct pollfd* fds,
    nfds_t nfds,
    int timeout,
    bool fail_badf)
{
    long ret = 0;
    myst_fdtable_t* fdtable;
    struct pollfd* tfds = NULL; /* target file descriptors */
    nfds_t tnfds = 0;           /* number of target file descriptors */
    size_t* tindices = NULL;    /* target indices */
    long tevents = 0;           /* the number of target events */
    long ievents = 0;           /* internal events */
    static myst_spinlock_t _lock;
    bool locked = false;
    long has_signals = 0;
    int original_timeout = timeout;
    struct timespec start;
    struct timespec end;
    long lapsed = 0;

    if (!fds && nfds)
        ERAISE(-EFAULT);

    if (!(fdtable = myst_fdtable_current()))
        ERAISE(-ENOSYS);

    if (!(tfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(tindices = calloc(nfds, sizeof(size_t))))
        ERAISE(-ENOMEM);

    myst_spin_lock(&_lock);
    locked = true;

    /* copy fds[] into arrays tfds[] array */
    for (nfds_t i = 0; i < nfds; i++)
    {
        int tfd = -1;
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;
        void* object;

        /* get the device for this file descriptor */
        int res = (myst_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object));

        if (res == -ENOENT)
            continue;

        // If we cannot find anything for this device we have two paths
        if (res == -EBADF)
        {
            // If it is called from SYS_select then we need to return an error
            // immediately, rather than letting the poll handle the errors; if
            // we dont we get stuck in a loop because sockets handle bad
            // descriptors differently than most other handles.
            if (fail_badf)
                ECHECK(-EBADF);
            else
            {
                tfd = INT_MAX;
                res = 0;
            }
        }

        ECHECK(res);

        /* inject special internal events if any */
        if (tfd != INT_MAX)
        {
            const int events = (*fdops->fd_get_events)(fdops, object);

            if (events >= 0)
            {
                fds[i].revents = (fds[i].events & events);
                ievents++;
                continue;
            }
        }

        /* get the target fd for this object */
        if (tfd == INT_MAX ||
            (tfd = (*fdops->fd_target_fd)(fdops, object)) >= 0)
        {
            tfds[tnfds].events = fds[i].events;
            tfds[tnfds].fd = tfd;
            tindices[tnfds] = i;
            tnfds++;
        }
    }

    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &start);

    if ((original_timeout > 500) || (original_timeout < 0))
        timeout = 500;
    else
        timeout = original_timeout;

    while (1)
    {
        myst_spin_unlock(&_lock);
        locked = false;

        /* If any internal events, do not sleep waiting for external events */
        if (ievents)
            timeout = 0;

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

        if (ievents > 0)
        {
            break;
        }

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

        // lapsed time needs to be milliseconds and this function returns
        // nanoseconds.
        lapsed += myst_lapsed_nsecs(&start, &end) / 1000000;

        if ((original_timeout > 0) && ((original_timeout - lapsed) <= 0))
            break;

        if (original_timeout > 0)
            timeout = original_timeout - lapsed;
        else
            timeout = 500;

        myst_spin_lock(&_lock);
        locked = true;
    }

    /* add target events and internal events */
    ret = tevents + ievents;

    /* update fds[] with the target events */
    for (nfds_t i = 0; i < tnfds; i++)
        fds[tindices[i]].revents = tfds[i].revents;

done:

    if (locked)
        myst_spin_unlock(&_lock);

    if (tfds)
        free(tfds);

    if (tindices)
        free(tindices);

    return ret;
}

long myst_syscall_poll(
    struct pollfd* fds,
    nfds_t nfds,
    int timeout,
    bool fail_badf)
{
    long ret = 0;
    long r;
    struct rlimit rlimit;

    ECHECK(myst_limit_get_rlimit(
        myst_process_self()->pid, RLIMIT_NOFILE, &rlimit));

    if (nfds > rlimit.rlim_max)
        ERAISE(-EINVAL);
    else if (
        nfds && fds && myst_is_bad_addr_read_write(fds, sizeof(*fds) * nfds))
        ERAISE(-EFAULT);

    ECHECK((r = _syscall_poll(fds, nfds, timeout, fail_badf)));

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
