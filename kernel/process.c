#include <libos/process.h>
#include <errno.h>

static int _ppid;
static int _pid;

pid_t libos_getpid(void)
{
    return _pid;
}

int libos_setpid(pid_t pid)
{
    if (pid <= 0)
        return -EINVAL;

    _pid = pid;
    return 0;
}

pid_t libos_getppid(void)
{
    return _ppid;
}

int libos_setppid(pid_t ppid)
{
    if (ppid <= 0)
        return -EINVAL;

    _ppid = ppid;
    return 0;
}
