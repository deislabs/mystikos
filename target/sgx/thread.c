#include <stdio.h>
#include <errno.h>
#include <libos/thread.h>
#include <libos/eraise.h>

long libos_run_thread(uint64_t cookie)
{
    long ret = 0;
    libos_thread_t* thread = (libos_thread_t*)cookie;

    if (!thread || thread->magic != LIBOS_THREAD_MAGIC || !thread->run)
        ERAISE(-EINVAL);

    ECHECK((*thread->run)(thread));

done:
    return ret;
}
