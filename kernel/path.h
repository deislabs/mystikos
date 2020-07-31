// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_PATH_H
#define _LIBOS_PATH_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

typedef struct _libos_path
{
    char buf[PATH_MAX];
} libos_path_t;

#endif /* _LIBOS_PATH_H */
