// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ONCE_H
#define _MYST_ONCE_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <myst/defs.h>

typedef uint32_t myst_once_t;

int myst_once(myst_once_t* once, void (*func)(void));

#endif /* _MYST_ONCE_H */
