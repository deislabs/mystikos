// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <string.h>

char* __strncpy_chk(char* dest, const char* src, size_t n, size_t destlen)
{
    assert(n <= destlen);
    return strncpy(dest, src, n);
}
