// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_REALPATH_H
#define _LIBOS_REALPATH_H

#include <libos/types.h>

int libos_realpath(const char* path, libos_path_t* resolved_path);

#endif /* _LIBOS_REALPATH_H */
