// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/trace.h>

static bool _trace = false;

void myst_set_trace(bool flag)
{
    _trace = flag;
}

bool myst_get_trace(void)
{
#if 1
    return _trace;
#else
    return true;
#endif
}
