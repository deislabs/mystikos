// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <string.h>

void* __memmove_chk(void* dest, const void* src, size_t n, size_t destlen)
{
    assert(n <= destlen);
    return memmove(dest, src, n);
}
