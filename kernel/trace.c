#include <libos/trace.h>
#include "common.h"

static bool _trace = true;

void libos_set_trace(bool flag)
{
    _trace = flag;
}

bool libos_get_trace(void)
{
    return _trace;
}
