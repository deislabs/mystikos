#include <myst/tcall.h>
#include <myst/thread.h>

long myst_tcall_interrupt_thread(pid_t tid)
{
    extern int myst_kill_thread(pid_t tid, int sig);
    return myst_kill_thread(tid, SIGUSR2);
}
