// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>

int __vprintf_chk(int flag, const char* format, va_list ap)
{
    return __vfprintf_chk(stdout, flag, format, ap);
}
