#include <myst/syscallext.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

int sched_getparam(pid_t pid, struct sched_param* param)
{
    return syscall(SYS_sched_getparam, pid, param);
}

int sched_setscheduler(pid_t pid, int sched, const struct sched_param* param)
{
    return syscall(SYS_sched_setscheduler, pid, sched, param);
}
