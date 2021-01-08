// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_UD2_H
#define _MYST_UD2_H

#include <myst/defs.h>

/* force undefined instruction crash */
MYST_INLINE void myst_ud2(void)
{
    __asm__ volatile("ud2" ::);
}

#endif /* _MYST_UD2_H */
