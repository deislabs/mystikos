// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/trace.h>
#include <stdio.h>
#include <string.h>

void myst_eraise(const char* file, uint32_t line, const char* func, int errnum)
{
    if (myst_get_trace())
    {
        if (errnum < 0)
            errnum = -errnum;

        printf(
            "ERAISE: %s(%u): %s: errno=%d: %s\n",
            file,
            line,
            func,
            errnum,
            myst_error_name(errnum));
    }
}
