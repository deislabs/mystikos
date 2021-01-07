// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CRASH_H
#define _MYST_CRASH_H

#include <myst/defs.h>

MYST_INLINE void myst_crash(void)
{
    *((volatile unsigned char*)0) = 0;
}

#endif /* _MYST_CRASH_H */
