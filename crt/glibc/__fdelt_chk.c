// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>

long int __fdelt_chk(long int d)
{
    if (d < 0 || d >= FD_SETSIZE)
    {
        assert("__fdelt_chk() panic" == NULL);
        abort();
    }

    return d / NFDBITS;
}
