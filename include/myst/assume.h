// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ASSUME_H
#define _MYST_ASSUME_H

#include <myst/crash.h>
#include <myst/types.h>

MYST_INLINE void myst_assume(bool cond)
{
    if (!cond)
        *((volatile unsigned char*)0) = 0;
}

#endif /* _MYST_ASSUME_H */
