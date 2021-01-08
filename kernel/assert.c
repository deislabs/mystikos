// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>

#include <myst/crash.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/strings.h>

void __assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func)
{
    myst_eprintf(
        "Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
    myst_crash();

    for (;;)
        ;
}
