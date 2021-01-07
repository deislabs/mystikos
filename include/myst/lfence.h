// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FENCE_H
#define _MYST_FENCE_H

#include <myst/types.h>

#define myst_lfence() __builtin_ia32_lfence()

#endif /* _MYST_FENCE_H */
