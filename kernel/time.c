#include <libos/syscall.h>
#include <libos/tcall.h>
#include <libos/time.h>

void libos_sleep_msec(uint64_t milliseconds)
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

    libos_tcall(SYS_nanosleep, params);
}
