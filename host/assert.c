// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void __libos_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func)
{
    fprintf(
        stderr, "Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
    abort();
}
