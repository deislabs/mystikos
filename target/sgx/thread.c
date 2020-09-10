#include <errno.h>
#include <libos/eraise.h>
#include <libos/thread.h>
#include <stdio.h>

long libos_run_thread(uint64_t cookie, pid_t tid, uint64_t event)
{
    long ret = 0;
    libos_thread_t* thread = (libos_thread_t*)cookie;

    if (!thread || thread->magic != LIBOS_THREAD_MAGIC || !thread->run)
        ERAISE(-EINVAL);

    ECHECK((*thread->run)(thread, tid, event));

done:
    return ret;
}
