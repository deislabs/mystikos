// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <errno.h>
#include <myst/clock.h>
#include <myst/syscall.h>
#include <stdio.h>

static long _realtime0 = 0;
static long _monotime0 = 0;
// The address of this pointer should be 8-byte aligned
// since it points to host address
static volatile long* _monotime_now = 0;
static long _realtime_delta = 0;
static long enc_clock_res = 0;

int myst_setup_clock(struct clock_ctrl* ctrl)
{
    // ctrl is a host address.
    // Store a copy of its content in enclave address to
    // avoid reading host memory multiple times.
    struct clock_ctrl* ctrl_enclave = NULL;
    int ret = -1;
    if (ctrl != NULL)
    {
        if (sizeof(struct clock_ctrl) % 8 != 0 || (uint64_t)ctrl % 8 != 0)
            return ret;

        if (!oe_is_outside_enclave(ctrl, sizeof(struct clock_ctrl)))
            return ret;

        // Make a copy of ctrl
        if (!(ctrl_enclave = malloc(sizeof(struct clock_ctrl))))
            return -ENOMEM;
        oe_memcpy_aligned(ctrl_enclave, ctrl, sizeof(struct clock_ctrl));

        // Only access enclave address here, instead of host, to isolate them
        // from attacks. Note the starting clocks don't account for
        // the time spent in entering the enclave.
        _realtime0 = ctrl_enclave->realtime0;
        _monotime0 = ctrl_enclave->monotime0;

        if (_realtime0 <= 0 || _monotime0 <= 0)
            goto done;

        // If ctrl is outside of the enclave, ctrl->now
        // should be outside too. _monotime_now is a host address. The address
        // is saved in the enclave, but we are still subject to malicious host's
        // manipulating of the value at the address, including but not limited
        // to, decreaing the value over time, i.e., a clock goes backward. Both
        // _get_monotime and _get_realtime are guarded against such attacks.
        _monotime_now = &ctrl->now;

        enc_clock_res = (long)ctrl_enclave->interval;

        ret = 0;
    }
done:
    if (ctrl_enclave)
        free(ctrl_enclave);

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
        // Changed resolution from 1 to 100 to address an issue
        // where uuid generation is not unique in Cpython
        prev += 100;
        return prev;
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

long myst_tcall_clock_getres(clockid_t clk_id, struct timespec* res)
{
    (void)clk_id;
    res->tv_sec = enc_clock_res / NANO_IN_SECOND;
    res->tv_nsec = enc_clock_res % NANO_IN_SECOND;
    return 0;
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_clock_gettime(clockid_t clk_id, struct timespec* tp)
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

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_clock_settime(clockid_t clk_id, struct timespec* tp)
{
    if (clk_id == CLOCK_REALTIME)
    {
        long new_time = tp->tv_sec * NANO_IN_SECOND + tp->tv_nsec;
        long cur_time = (long)_get_realtime();

        if (new_time <= cur_time)
            return 0; // trying to set clock backward, make it no-op

        /* possible overflow, make it no-op */
        if (__builtin_add_overflow(
                _realtime_delta, (new_time - cur_time), &_realtime_delta))
        {
            return -EINVAL; // possible overflow, make it no-op
        }

        return 0;
    }

    // Clocks other than CLOCK_REALTIME are not settable
    return -EINVAL;
}
