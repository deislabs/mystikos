// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <errno.h>
#include <libos/clock.h>
#include <libos/syscall.h>
#include <libos/syscallext.h>
#include <stdio.h>

static long _realtime0 = 0;
static long _monotime0 = 0;
static volatile long* _monotime_now = 0;
static long _realtime_delta = 0;

int libos_setup_clock(struct clock_ctrl* ctrl)
{
    int ret = -1;
    if (ctrl != NULL)
    {
        if (!oe_is_outside_enclave(ctrl, sizeof(struct clock_ctrl)))
            return ret;

        // Copy the starting values into enclave to isolate them
        // From attacks. Note the starting clocks don't account for
        // the time spent in entering the enclave.
        _realtime0 = ctrl->realtime0;
        _monotime0 = ctrl->monotime0;

        if (_realtime0 <= 0 || _monotime0 <= 0)
            goto done;

        // If ctrl is outside of the enclave, ctrl->now
        // should be outside too. _monotime_now is a host address. The address
        // is saved in the enclave, but we are still subject to malicious host's
        // manipulating of the value at the address, including but not limited
        // to, decreaing the value over time, i.e., a clock goes backward. Both
        // _get_monotime and _get_realtime are guarded against such attacks.
        _monotime_now = &ctrl->now;

        ret = 0;
    }
done:
    return ret;
}

static void _check(bool overflowed)
{
    if (overflowed)
    {
        fprintf(stderr, "clock overflow\n");
        oe_abort();
    }
}

/* Return monotonic clock in nanoseconds since a starting point */
static long _get_monotime()
{
    static long prev = 0;
    if (prev == 0)
        prev = _monotime0;
    long now = *_monotime_now;
    if (now > prev)
    {
        prev = now;
        return now;
    }
    else
    {
        // maintain monotonicity.
        // TODO: issue a warning. Host might be playing tricks.
        return ++prev;
    }
}

static long _get_boottime()
{
    /* Boottime clock relies on monotonic clock */
    return _get_monotime();
}

/* Return realtime clock in nanoseconds since the epoch */
static long _get_realtime()
{
    // Derive the realtime clock from the monotonic clock.
    // Any adjustment to the system clock is invisible to the
    // enclave application once it is launched.
    long ret = _get_monotime() - _monotime0;
    _check(__builtin_saddl_overflow(ret, _realtime0, &ret));
    _check(__builtin_saddl_overflow(ret, _realtime_delta, &ret));
    return ret;
}

/* This overrides the weak version in liboskernel.a */
long libos_tcall_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    long nanoseconds;
    switch (clk_id)
    {
        case CLOCK_MONOTONIC_COARSE:
        case CLOCK_MONOTONIC:
        {
            nanoseconds = _get_monotime();
            break;
        }
        case CLOCK_REALTIME_COARSE:
        case CLOCK_REALTIME:
        {
            nanoseconds = _get_realtime();
            break;
        }
        case CLOCK_BOOTTIME:
        {
            nanoseconds = _get_boottime();
            break;
        }
        default:
            return -EINVAL;
    }

    tp->tv_sec = nanoseconds / NANO_IN_SECOND;
    tp->tv_nsec = nanoseconds % NANO_IN_SECOND;

    return 0;
}

/* This overrides the weak version in liboskernel.a */
long libos_tcall_clock_settime(clockid_t clk_id, struct timespec* tp)
{
    if (clk_id == CLOCK_REALTIME)
    {
        long new_time = tp->tv_sec * NANO_IN_SECOND + tp->tv_nsec;
        long cur_time = (long)_get_realtime();

        if (new_time <= cur_time)
            return 0; // trying to set clock backward, make it no-op

        if (_realtime_delta > _realtime_delta + (new_time - cur_time))
            return -EINVAL; // possible overflow, make it no-op

        _realtime_delta += (new_time - cur_time);
        return 0;
    }

    // Clocks other than CLOCK_REALTIME are not settable
    return -EINVAL;
}
