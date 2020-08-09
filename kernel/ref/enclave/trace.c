#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include "posix_trace.h"
#include "posix_mutex.h"

#include "posix_warnings.h"

static posix_mutex_t _lock;

void posix_print_backtrace(void)
{
    posix_mutex_lock(&_lock);
    posix_printf("==================\n");
    oe_print_backtrace();
    posix_printf("==================\n");
    posix_mutex_unlock(&_lock);
}

void posix_set_trace(uint32_t value)
{
    static posix_spinlock_t _lock;

    posix_spin_lock(&_lock);

    if (!posix_self() || !posix_self()->shared_block)
    {
        for (;;)
            ;
    }
    posix_self()->shared_block->trace = value;

    posix_spin_unlock(&_lock);
}
