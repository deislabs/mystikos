// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_CRASH_H
#define _LIBOS_CRASH_H

#include <libos/defs.h>

LIBOS_INLINE void libos_crash(void)
{
    *((volatile unsigned char*)0) = 0;
}

#endif /* _LIBOS_CRASH_H */
