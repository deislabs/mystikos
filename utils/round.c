#include <errno.h>
#include <libos/round.h>

int libos_round_up(uint64_t x, uint64_t m, uint64_t* r)
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
int libos_round_up_signed(int64_t x, int64_t m, int64_t* r)
{
    int64_t t;

    if (!r || x < 0 || m < 0)
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
