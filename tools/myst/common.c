// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

int myst_expand_size_string_to_ulong(const char* size_string, size_t* size)
{
    char* endptr = NULL;
    *size = strtoul(size_string, &endptr, 10);
    if (endptr[0] == '\0')
    {
        // nothing to do... in bytes
    }
    else if (strcasecmp(endptr, "k") == 0)
    {
        *size *= 1024;
    }
    else if (strcasecmp(endptr, "m") == 0)
    {
        *size *= 1024;
        *size *= 1024;
    }
    else if (strcasecmp(endptr, "g") == 0)
    {
        *size *= 1024;
        *size *= 1024;
        *size *= 1024;
    }
    else
    {
        return -1;
    }

    return 0;
}
