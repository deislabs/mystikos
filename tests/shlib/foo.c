// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdint.h>
#include <stdio.h>

uint64_t foo()
{
    extern uint64_t goo();
    return goo();
}
