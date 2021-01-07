// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include <myst/round.h>

void test_rounding(void)
{
    uint64_t r;
    int64_t rs;

    /* round 0 to next multiple of 4096 */
    r = 0;
    assert(myst_round_up(0, 4096, &r) == 0);
    assert(r == 0);

    /* round 4097 to next multiple of 4096 */
    r = 0;
    assert(myst_round_up(4097, 4096, &r) == 0);
    assert(r == 8192);

    /* round up to the maximum value */
    r = 0;
    uint64_t x = ULONG_MAX - 4095;
    assert(myst_round_up(x, 4096, &r) == 0);
    assert(r == x);
    assert((r % 4096) == 0);

    /* test null r parameter */
    r = 0;
    assert(myst_round_up(0, 0, NULL) == -EINVAL);

    /* test divide-by-zero */
    r = 0;
    assert(myst_round_up(0, 0, &r) == -ERANGE);

    /* test overflow */
    r = 0;
    assert(myst_round_up(ULONG_MAX, 4096, &r) == -ERANGE);

    /* test null r parameter */
    assert(myst_round_up_signed(0, 8, NULL) == -EINVAL);

    /* test negative x parameter */
    rs = 0;
    assert(myst_round_up_signed(-1, 4096, &rs) == -EINVAL);

    /* test negative m parameter */
    rs = 0;
    assert(myst_round_up_signed(8, -8, &rs) == -EINVAL);

    /* test signed overflow */
    rs = 0;
    assert(myst_round_up_signed(LONG_MAX, 4096, &rs) == -ERANGE);
}

int main(int argc, const char* argv[])
{
    test_rounding();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
