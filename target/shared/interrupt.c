#include <sys/syscall.h>

#include <myst/tcall.h>
#include <myst/thread.h>

long myst_tcall_interrupt_thread(pid_t tid)
{
    int ret = syscall(SYS_tkill, tid, MYST_INTERRUPT_THREAD_SIGNAL);

    if (ret < 0)
        ret = -errno;

    return ret;
}
