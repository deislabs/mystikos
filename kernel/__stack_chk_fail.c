// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/panic.h>
#include <myst/strings.h>
#include <myst/thread.h>

void __stack_chk_fail(void)
{
    myst_panic("__stack_chk_fail()");
}
