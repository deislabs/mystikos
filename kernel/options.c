#include <libos/options.h>

static bool _real_syscalls;

bool libos_get_real_syscalls(void)
{
    return _real_syscalls;
}

void libos_set_real_syscalls(bool flag)
{
    _real_syscalls = flag;
}
