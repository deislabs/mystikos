// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_FENCE_H
#define _LIBOS_FENCE_H

#include <libos/types.h>

#define libos_lfence() __builtin_ia32_lfence()

#endif /* _LIBOS_FENCE_H */
