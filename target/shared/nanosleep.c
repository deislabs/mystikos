#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>

#include <myst/eraise.h>
#include <myst/tcall.h>
#include <myst/times.h>

long myst_tcall_nanosleep(const struct timespec* req, struct timespec* rem)
{
    long ret = 0;
    int retval;
    struct timespec ts0;
    struct timespec ts1;
    int err;

    /* check req parameter for nullness */
    if (!req)
        ERAISE(-EINVAL);

    /* check the req parameter (as required by nanosleep manual page) */
    if (req->tv_sec < 0 || !(req->tv_nsec >= 0 && req->tv_nsec <= 999999999))
        ERAISE(-EINVAL);

    /* get the start time if needed */
    if (rem && clock_gettime(CLOCK_REALTIME, &ts0) != 0)
        ERAISE(-ENOSYS);

    /* sleep until timeout or signal */
    {
        sigset_t sigmask;

        /* Temporarily unblock SIGUSR2 (use sigmask without SIGUSR2) */
        sigemptyset(&sigmask);

        if ((retval = ppoll(NULL, 0, req, &sigmask)) >= 0)
        {
            ret = retval;
            goto done;
        }

        err = errno;
    }

    /* rem is non-null and interrupted by a signal */
    if (rem && err == EINTR)
    {
        /* get the end time */
        if (clock_gettime(CLOCK_REALTIME, &ts1) != 0)
            ERAISE(-ENOSYS);

        /* set the remaining time */
        {
            const long nanos = timespec_to_nanos(req);
            const long nanos0 = timespec_to_nanos(&ts0);
            const long nanos1 = timespec_to_nanos(&ts1);
            const long delta = nanos1 - nanos0;

            if (delta < nanos)
                nanos_to_timespec(rem, nanos - delta);
        }
    }

    ret = -err;

done:

    return ret;
}
