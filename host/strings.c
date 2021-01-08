// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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
