// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_ONCE_H
#define _LIBOS_ONCE_H

#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include <libos/defs.h>

typedef uint32_t libos_once_t;

int libos_once(libos_once_t* once, void (*func)(void));

#endif /* _LIBOS_ONCE_H */
