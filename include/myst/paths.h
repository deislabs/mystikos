// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PATHS_H
#define _MYST_PATHS_H

#include <limits.h>

int myst_path_absolute_cwd(
    const char* cwd,
    const char* path,
    char* buf,
    size_t size);

/* find the absolute path relative to the current working directory */
int myst_path_absolute(const char* path, char* buf, size_t size);

/* Normalize the path (removing "." and ".." elements) */
int myst_tok_normalize(const char* toks[]);

int myst_normalize(const char* path, char* buf, size_t size);

const char* myst_basename(const char* path);

int myst_split_path(
    const char* path,
    char dirname[PATH_MAX],
    char basename[PATH_MAX]);

#endif /* _MYST_PATHS_H */
