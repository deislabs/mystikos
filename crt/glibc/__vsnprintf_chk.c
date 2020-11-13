// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>

int __vsnprintf_chk(
    char* s,
    size_t size,
    int flag,
    size_t slen,
    const char* format,
    va_list ap)
{
    return vsnprintf(s, size, format, ap);
}
