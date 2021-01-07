// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LSR_H
#define _MYST_LSR_H

#include <myst/strarr.h>
#include <myst/types.h>
#include <stdbool.h>

int myst_lsr(const char* root, myst_strarr_t* paths, bool include_dirs);

#endif /* _MYST_LSR_H */
