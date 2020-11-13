// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_ASSUME_H
#define _LIBOS_ASSUME_H

#include <libos/crash.h>
#include <libos/types.h>

LIBOS_INLINE void libos_assume(bool cond)
{
    if (!cond)
        *((volatile unsigned char*)0) = 0;
}

#endif /* _LIBOS_ASSUME_H */
