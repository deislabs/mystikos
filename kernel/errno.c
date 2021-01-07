// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>

#include <myst/tcall.h>
#include <myst/thread.h>

int* __errno_location(void)
{
    int* ptr = NULL;

    myst_assume(myst_tcall_get_errno_location(&ptr) == 0);
    myst_assume(ptr != 0);

    return ptr;
}
