// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/defs.h>
#include <myst/gcov.h>

MYST_WEAK
void gcov_set_stderr(FILE* stream)
{
    (void)stream;
}

MYST_WEAK
void gcov_set_libc(libc_t* libc)
{
    (void)libc;
}
