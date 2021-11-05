// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myst/strings.h>

static void _test_strtod(void)
{
    char* end;
    char buf[64];

    /* 1.2 */
    {
        double x = myst_strtod("1.2", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "1.20000") == 0);
        assert(*end == '\0');
    }

    /* 123.456 */
    {
        double x = myst_strtod("123.456", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "123.45600") == 0);
        assert(*end == '\0');
    }

    /* 123. */
    {
        double x = myst_strtod("123.00000", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "123.00000") == 0);
        assert(*end == '\0');
    }

    /* -123. */
    {
        double x = myst_strtod("-123.00000", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "-123.00000") == 0);
        assert(*end == '\0');
    }

    /* +123. */
    {
        double x = myst_strtod("+123.00000", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "123.00000") == 0);
        assert(*end == '\0');
    }

    /* 123456. */
    {
        double x = myst_strtod(".123456", &end);
        snprintf(buf, sizeof(buf), "%.6lf", x);
        assert(strcmp(buf, "0.123456") == 0);
        assert(*end == '\0');
    }

    /* 0 */
    {
        double x = myst_strtod("0", &end);
        snprintf(buf, sizeof(buf), "%.6lf", x);
        assert(strcmp(buf, "0.000000") == 0);
        assert(*end == '\0');
    }

    /* 1 */
    {
        double x = myst_strtod("1", &end);
        snprintf(buf, sizeof(buf), "%.6lf", x);
        assert(strcmp(buf, "1.000000") == 0);
        assert(*end == '\0');
    }

    /* "" */
    {
        double x = myst_strtod("", &end);
        snprintf(buf, sizeof(buf), "%.6lf", x);
        assert(strcmp(buf, "0.000000") == 0);
        assert(*end == '\0');
    }

    /* ".123" */
    {
        double x = myst_strtod(".123", &end);
        snprintf(buf, sizeof(buf), "%.6lf", x);
        assert(strcmp(buf, "0.123000") == 0);
        assert(*end == '\0');
    }

    /* . */
    {
        double x = myst_strtod(".", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "0.00000") == 0);
        assert(*end == '\0');
    }

    /* -0 */
    {
        double x = myst_strtod("-0", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "0.00000") == 0);
        assert(*end == '\0');
    }

    /* 123xyz */
    {
        double x = myst_strtod("123xyz", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "123.00000") == 0);
        assert(*end == 'x');
    }

    /* 123.xyz */
    {
        double x = myst_strtod("123.xyz", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "123.00000") == 0);
        assert(*end == 'x');
    }

    /* .123xyz */
    {
        double x = myst_strtod(".123xyz", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "0.12300") == 0);
        assert(*end == 'x');
    }

    /* -123.456 */
    {
        double x = myst_strtod("-123.45600", &end);
        snprintf(buf, sizeof(buf), "%.5lf", x);
        assert(strcmp(buf, "-123.45600") == 0);
        assert(*end == '\0');
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

static void _test_strtoul(void)
{
    char* end;
    char buf[64];

    /* 12345 */
    {
        unsigned long x = myst_strtoul("12345", &end, 10);
        snprintf(buf, sizeof(buf), "%ld", x);
        assert(strcmp(buf, "12345") == 0);
    }

    /* 0 */
    {
        unsigned long x = myst_strtoul("0", &end, 10);
        snprintf(buf, sizeof(buf), "%lu", x);
        assert(strcmp(buf, "0") == 0);
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

static void _test_strtol(void)
{
    char* end;
    char buf[64];

    /* 12345 */
    {
        long x = myst_strtol("12345", &end, 10);
        snprintf(buf, sizeof(buf), "%ld", x);
        assert(strcmp(buf, "12345") == 0);
    }

    /* -12345 */
    {
        long x = myst_strtol("-12345", &end, 10);
        snprintf(buf, sizeof(buf), "%ld", x);
        assert(strcmp(buf, "-12345") == 0);
    }

    /* +12345 */
    {
        long x = myst_strtol("+12345", &end, 10);
        snprintf(buf, sizeof(buf), "%ld", x);
        assert(strcmp(buf, "12345") == 0);
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    _test_strtod();
    _test_strtoul();
    _test_strtol();

    printf("=== passed all tests (%s)\n", argv[0]);
    return 0;
}
