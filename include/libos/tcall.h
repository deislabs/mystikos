// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_TCALL_H
#define _LIBOS_TCALL_H

#include <libos/defs.h>
#include <stddef.h>
#include <stdint.h>

typedef enum libos_tcall_number
{
    LIBOS_TCALL_RANDOM = 2048,
    LIBOS_TCALL_THREAD_SELF,
}
libos_tcall_number_t;

long libos_tcall(long n, long params[6]);

LIBOS_INLINE long libos_tcall_random(void* data, size_t size)
{
    long params[6] = { (long)data, (long)size };
    return libos_tcall(LIBOS_TCALL_RANDOM, params);
}

LIBOS_INLINE long libos_tcall_thread_self(void)
{
    long params[6] = { 0 };
    return libos_tcall(LIBOS_TCALL_THREAD_SELF, params);
}

#endif /* _LIBOS_TCALL_H */
