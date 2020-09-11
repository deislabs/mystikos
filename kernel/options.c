#include <libos/options.h>

static bool _real_syscalls;
static bool _export_ramfs;

bool libos_get_real_syscalls(void)
{
    return _real_syscalls;
}

void libos_set_real_syscalls(bool flag)
{
    _real_syscalls = flag;
}

bool libos_get_export_ramfs(void)
{
    return _export_ramfs;
}

void libos_set_export_ramfs(bool flag)
{
    _export_ramfs = flag;
}
