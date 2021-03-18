#include <limits.h>
#include <stdio.h>

#include <myst/eraise.h>
#include <myst/timeval.h>

#define USEC 1000000

int myst_timeval_to_uint64(const struct timeval* tv, uint64_t* x)
{
    int ret = 0;
    struct timeval buf;
    uint64_t mult;
    uint64_t add;

    if (x)
        *x = 0;

    if (!tv || !x)
        ERAISE(-EINVAL);

    /* reject negative timeval fields */
    if (tv->tv_sec < 0 || tv->tv_usec < 0)
        ERAISE(-EINVAL);

    /* normalize the timeval */
    buf = *tv;
    buf.tv_sec += buf.tv_usec / USEC;
    buf.tv_usec = buf.tv_usec % USEC;

    /* Check for overflow on multiply */
    if (__builtin_mul_overflow((uint64_t)buf.tv_sec, (uint64_t)USEC, &mult))
        ERAISE(-ERANGE);

    /* Check for overflow on add */
    if (__builtin_add_overflow((uint64_t)buf.tv_usec, mult, &add))
        ERAISE(-ERANGE);

    *x = add;

done:
    return ret;
}

int myst_uint64_to_timeval(uint64_t x, struct timeval* tv)
{
    int ret = 0;

    if (tv)
    {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }

    if (!tv)
        ERAISE(-EINVAL);

    tv->tv_sec = x / USEC;
    tv->tv_usec = x % USEC;

done:
    return ret;
}
