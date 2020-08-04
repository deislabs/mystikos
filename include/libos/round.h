#ifndef _LIBOS_ROUND_H
#define _LIBOS_ROUND_H

#include <libos/types.h>

static inline uint64_t libos_round_up_u64(uint64_t x, uint64_t m)
{
    return (x + m - 1) / m * m;
}

static inline off_t libos_round_up_off(off_t x, off_t m)
{
    return (x + m - 1) / m * m;
}

static inline int64_t libos_round_up_i64(int64_t x, int64_t m)
{
    return (x + m - 1) / m * m;
}

#endif /* _LIBOS_ROUND_H */
