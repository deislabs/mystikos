// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FUTEX_H
#define _MYST_FUTEX_H

#include <myst/types.h>
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
#define FUTEX_WAKE_BITSET    10
#define FUTEX_PRIVATE        128
#define FUTEX_CLOCK_REALTIME 256
// clang-format on

#define FUTEX_BITSET_MATCH_ANY 0xffffffff

int myst_futex_wait(int* uaddr, int val, const struct timespec* to);
int myst_futex_wait_ops(
    int* uaddr,
    int val,
    const struct timespec* to,
    uint32_t bitset);

int myst_futex_wake(int* uaddr, int val);
int myst_futex_wake_ops(int* uaddr, int val, uint32_t bitset);

#endif /* _MYST_FUTEX_H */
