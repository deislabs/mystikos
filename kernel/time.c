// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/signal.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/time.h>

void myst_sleep_msec(uint64_t milliseconds, bool process_signals)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    static const uint64_t _SEC_TO_MSEC = 1000UL;
    static const uint64_t _MSEC_TO_NSEC = 1000000UL;
    long params[6];

    ts.tv_sec = (time_t)(milliseconds / _SEC_TO_MSEC);
    ts.tv_nsec = (long)((milliseconds % _SEC_TO_MSEC) * _MSEC_TO_NSEC);

    params[0] = (long)req;
    params[1] = (long)NULL;

    while (myst_tcall(SYS_nanosleep, params) == -EINTR)
    {
        if (process_signals)
            myst_signal_process(myst_thread_self());
    }
}
