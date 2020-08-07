// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_PATHS_H
#define _LIBOS_PATHS_H

#include <libos/types.h>

#define LIBOS_PATHS_MAX_COMPONENTS 64

/* find the absolute path relative to the current working directory */
int libos_path_absolute(const char* path, char* buf, size_t size);

/* Normalize the path (removing "." and ".." elements) */
int libos_path_normalize(const char* toks[]);

#endif /* _LIBOS_PATHS_H */
