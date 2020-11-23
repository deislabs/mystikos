// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_TYPES_H
#define _LIBOS_TYPES_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct _libos_path
{
    char buf[PATH_MAX];
} libos_path_t;

#endif /* _LIBOS_TYPES_H */
