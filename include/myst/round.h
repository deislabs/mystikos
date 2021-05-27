// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ROUND_H
#define _MYST_ROUND_H

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/user.h>

#include <myst/defs.h>

static __inline__ uint64_t myst_round_down_to_page_size(uint64_t x)
{
    return x & ~((uint64_t)PAGE_SIZE - 1);
}

/* round x up to next multiple of m (possible x itself) */
static __inline__ int myst_round_up(uint64_t x, uint64_t m, uint64_t* r)
{
    uint64_t t;

    if (!r)
        return -EINVAL;

    /* prevent divide by zero */
    if (m == 0)
        return -ERANGE;

    if (__builtin_add_overflow(x, m - 1, &t))
        return -ERANGE;

    if (__builtin_mul_overflow(t / m, m, r))
        return -ERANGE;

    return 0;
}

/* round x up to next multiple of m (possible x itself) */
int myst_round_up_signed(int64_t x, int64_t m, int64_t* r);

#endif /* _MYST_ROUND_H */
