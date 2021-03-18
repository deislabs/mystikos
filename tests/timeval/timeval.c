// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include <myst/timeval.h>

int main(int argc, const char* argv[])
{
    printf("=== passed test (%s)\n", argv[0]);

    /* test zero value */
    {
        struct timeval tv = {0, 0};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == 0);
        assert(x == 0);

        struct timeval tv2;
        assert(myst_uint64_to_timeval(x, &tv2) == 0);
        assert(tv2.tv_sec == tv.tv_sec);
        assert(tv2.tv_usec == tv.tv_usec);
    }

    /* test just tv_usec field */
    {
        struct timeval tv = {0, 999};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == 0);
        assert(x == 999);

        struct timeval tv2;
        assert(myst_uint64_to_timeval(x, &tv2) == 0);
        assert(tv2.tv_sec == tv.tv_sec);
        assert(tv2.tv_usec == tv.tv_usec);
    }

    /* test just tv_sec field */
    {
        struct timeval tv = {3, 0};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == 0);
        assert(x == 3000000);

        struct timeval tv2;
        assert(myst_uint64_to_timeval(x, &tv2) == 0);
        assert(tv2.tv_sec == tv.tv_sec);
        assert(tv2.tv_usec == tv.tv_usec);
    }

    /* test both tv_sec and tv_usec fields */
    {
        struct timeval tv = {12345, 999999};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == 0);
        assert(x == 12345999999);

        struct timeval tv2;
        assert(myst_uint64_to_timeval(x, &tv2) == 0);
        assert(tv2.tv_sec == tv.tv_sec);
        assert(tv2.tv_usec == tv.tv_usec);
    }

    /* test oversized tv_usec field */
    {
        struct timeval tv = {12345, 4000000};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == 0);
        assert(x == 12349000000);

        struct timeval tv2;
        assert(myst_uint64_to_timeval(x, &tv2) == 0);
        assert(tv2.tv_sec == 12349);
        assert(tv2.tv_usec == 0);
    }

    /* test large values */
    {
        struct timeval tv = {18446744073708, 999999};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == 0);
        assert(x == 18446744073708999999UL);

        struct timeval tv2;
        assert(myst_uint64_to_timeval(x, &tv2) == 0);
        assert(tv2.tv_sec == tv.tv_sec);
        assert(tv2.tv_usec == tv.tv_usec);
    }

    /* test max case */
    {
        struct timeval tv = {MYST_TIMEVAL_MAX_SEC, MYST_TIMEVAL_MAX_USEC};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == 0);
        assert(x == UINT64_MAX);

        struct timeval tv2;
        assert(myst_uint64_to_timeval(x, &tv2) == 0);
        assert(tv2.tv_sec == tv.tv_sec);
        assert(tv2.tv_usec == tv.tv_usec);
    }

    /* test max constants */
    {
        struct timeval tv;
        const uint64_t x = UINT64_MAX;
        assert(myst_uint64_to_timeval(x, &tv) == 0);
        assert(tv.tv_sec == MYST_TIMEVAL_MAX_SEC);
        assert(tv.tv_usec == MYST_TIMEVAL_MAX_USEC);
    }

    /* test overflow case 1 */
    {
        struct timeval tv = {MYST_TIMEVAL_MAX_SEC + 1, MYST_TIMEVAL_MAX_USEC};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == -ERANGE);
    }

    /* test overflow case 2 */
    {
        struct timeval tv = {MYST_TIMEVAL_MAX_SEC, MYST_TIMEVAL_MAX_USEC + 1};
        uint64_t x;
        assert(myst_timeval_to_uint64(&tv, &x) == -ERANGE);
    }

    return 0;
}
