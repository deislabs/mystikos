// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_LSR_H
#define _LIBOS_LSR_H

#include <libos/strarr.h>
#include <libos/types.h>
#include <stdbool.h>

int libos_lsr(const char* root, libos_strarr_t* paths, bool include_dirs);

#endif /* _LIBOS_LSR_H */
