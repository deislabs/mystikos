// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_ROUND_H
#define _LIBOS_ROUND_H

#include <stdint.h>
#include <limits.h>
#include <sys/user.h>

#include <libos/defs.h>

static __inline__ uint64_t libos_round_down_to_page_size(uint64_t x)
{
    return x & ~((uint64_t)PAGE_SIZE - 1);
}

/* round x up to next multiple of m (possible x itself) */
int libos_round_up(uint64_t x, uint64_t m, uint64_t* r);

/* round x up to next multiple of m (possible x itself) */
int libos_round_up_signed(int64_t x, int64_t m, int64_t* r);

#endif /* _LIBOS_ROUND_H */
