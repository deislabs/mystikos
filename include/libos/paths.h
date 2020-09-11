// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_PATHS_H
#define _LIBOS_PATHS_H

#include <libos/types.h>

int libos_path_absolute_cwd(
    const char* cwd,
    const char* path,
    char* buf,
    size_t size);

/* find the absolute path relative to the current working directory */
int libos_path_absolute(const char* path, char* buf, size_t size);

/* Normalize the path (removing "." and ".." elements) */
int libos_tok_normalize(const char* toks[]);

int libos_normalize(const char* path, char* buf, size_t size);

const char* libos_basename(const char* path);

#endif /* _LIBOS_PATHS_H */
