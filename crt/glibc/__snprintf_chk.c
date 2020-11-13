// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

int __snprintf_chk(
    char* str,
    size_t size,
    int flags,
    size_t slen,
    const char* format,
    ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vsnprintf(str, size, format, ap);
    va_end(ap);

    return r;
}
