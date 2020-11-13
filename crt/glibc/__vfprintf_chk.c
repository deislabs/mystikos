// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>

int __vfprintf_chk(FILE* fp, int flag, const char* format, va_list ap)
{
    return vfprintf(fp, format, ap);
}
