#include <myst/syscallext.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

int sched_getscheduler(pid_t pid)
{
    return syscall(SYS_sched_getscheduler, pid);
}

int sched_setscheduler(pid_t pid, int sched, const struct sched_param* param)
{
    return syscall(SYS_sched_setscheduler, pid);
}

int sched_getparam(pid_t pid, struct sched_param* param)
{
    if (param)
        memset(param, 0, sizeof(struct sched_param));

    return syscall(SYS_sched_getparam, pid, param);
}
