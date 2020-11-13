// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <libos/defs.h>
#include <libos/gcov.h>

LIBOS_WEAK
void gcov_set_stderr(FILE* stream)
{
    (void)stream;
}

LIBOS_WEAK
void gcov_set_libc(libc_t* libc)
{
    (void)libc;
}
