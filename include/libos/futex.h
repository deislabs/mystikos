// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_FUTEX_H
#define _LIBOS_FUTEX_H

#include <libos/types.h>
#include <time.h>

// clang-format off
#define FUTEX_WAIT           0
#define FUTEX_WAKE           1
#define FUTEX_FD             2
#define FUTEX_REQUEUE        3
#define FUTEX_CMP_REQUEUE    4
#define FUTEX_WAKE_OP        5
#define FUTEX_LOCK_PI        6
#define FUTEX_UNLOCK_PI      7
#define FUTEX_TRYLOCK_PI     8
#define FUTEX_WAIT_BITSET    9
#define FUTEX_PRIVATE        128
#define FUTEX_CLOCK_REALTIME 256
// clang-format on

int libos_futex_wait(int* uaddr, int val, const struct timespec* to);

int libos_futex_wake(int* uaddr, int val);

#endif /* _LIBOS_FUTEX_H */
