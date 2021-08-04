// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TRACE_H
#define _MYST_TRACE_H

#include <myst/defs.h>
#include <myst/printf.h>

MYST_INLINE void __myst_trace(
    const char* file,
    unsigned int line,
    const char* func)
{
    myst_eprintf("__myst_trace(): %s(%u): %s()\n", file, line, func);
}

#define MYST_TRACE __myst_trace(__FILE__, __LINE__, __FUNCTION__)

void myst_set_trace(bool flag);

bool myst_get_trace(void);

#endif /* _MYST_TRACE_H */
