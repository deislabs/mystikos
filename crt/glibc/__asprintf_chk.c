// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>

int __asprintf_chk(char** strp, int flag, const char* fmt, ...)
{
    int r;

    va_list ap;
    va_start(ap, fmt);
    r = vasprintf(strp, fmt, ap);
    va_end(ap);

    return r;
}
