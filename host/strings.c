// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/strings.h>

char* myst_strdup(const char* s)
{
    return strdup(s);
}

int myst_eprintf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vfprintf(stderr, format, ap);
    va_end(ap);

    return n;
}

int myst_printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vfprintf(stdout, format, ap);
    va_end(ap);

    return n;
}

int myst_str2int(const char* s, int* x)
{
    int ret = 0;
    long tmp;
    ECHECK(myst_str2long(s, &tmp));

    if (tmp < INT_MIN || tmp > INT_MAX)
        ERAISE(-ERANGE);

    *x = (int)tmp;

done:
    return ret;
}

int myst_str2long(const char* s, long* x)
{
    int ret = 0;
    char* end;
    long tmp = strtol(s, &end, 10);

    if (!end || *end)
        ERAISE(-EINVAL);

    *x = tmp;

done:
    return ret;
}