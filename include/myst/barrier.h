// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BARRIER_H
#define _MYST_BARRIER_H

#include <myst/types.h>

#define myst_barrier() __asm__ volatile("" : : : "memory")

#endif /* _MYST_BARRIER_H */
