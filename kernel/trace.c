#include <libos/deprecated.h>
#include <libos/trace.h>

static bool _trace = false;

void libos_set_trace(bool flag)
{
    _trace = flag;
}

bool libos_get_trace(void)
{
    return _trace;
}
