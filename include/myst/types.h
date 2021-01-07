// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TYPES_H
#define _MYST_TYPES_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct _myst_path
{
    char buf[PATH_MAX];
} myst_path_t;

#endif /* _MYST_TYPES_H */
