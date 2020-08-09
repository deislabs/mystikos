#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/defs.h>
#include "posix_time.h"
#include "posix_io.h"
#include "posix_ocalls.h"
#include "posix_ocall_structs.h"
#include "posix_panic.h"
#include "posix_signal.h"

#include "posix_warnings.h"

OE_STATIC_ASSERT(sizeof(struct timespec) == sizeof(struct posix_timespec));
OE_CHECK_FIELD(struct timespec, struct posix_timespec, tv_sec);
OE_CHECK_FIELD(struct timespec, struct posix_timespec, tv_nsec);
OE_STATIC_ASSERT(sizeof(clockid_t) == sizeof(int));

int posix_nanosleep(const struct timespec* req, struct timespec* rem)
{
    int retval;
    const struct posix_timespec* preq = (const struct posix_timespec*)req;
    struct posix_timespec* prem = (struct posix_timespec*)rem;

    if (posix_nanosleep_ocall(&retval, preq, prem) != OE_OK)
    {
        POSIX_PANIC("unexpected");
        return -EINVAL;
    }

    posix_dispatch_signal();

    return retval;
}

int posix_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    int retval;
    struct posix_timespec* ptp = (struct posix_timespec*)tp;

    if (posix_clock_gettime_ocall(&retval, clk_id, ptp) != OE_OK)
        return -ENOSYS;

    return retval;
}
