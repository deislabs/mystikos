// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_REALPATH_H
#define _MYST_REALPATH_H

#include <myst/types.h>

int myst_realpath(const char* path, myst_path_t* resolved_path);

#endif /* _MYST_REALPATH_H */
