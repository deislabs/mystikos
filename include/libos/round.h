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

static inline const void* libos_round_up_ptr(const void* x, uint64_t m)
{
    return (void*)(((uint64_t)x + m - 1) / m * m);
}

static inline int64_t libos_round_up_i64(int64_t x, int64_t m)
{
    return (x + m - 1) / m * m;
}

static inline uint64_t libos_round_up_to_page_size(uint64_t x)
{
    uint64_t n = LIBOS_PAGE_SIZE;
    return (x + n - 1) / n * n;
}

static inline uint64_t libos_round_down_to_page_size(uint64_t x)
{
    return x & ~((uint64_t)LIBOS_PAGE_SIZE - 1);
}

#endif /* _LIBOS_ROUND_H */
