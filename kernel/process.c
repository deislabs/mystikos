#include <libos/process.h>
#include <errno.h>

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
