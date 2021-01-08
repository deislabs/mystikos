// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CWD_H
#define _MYST_CWD_H

#include <myst/types.h>

int myst_chdir(const char* path);

char* myst_getcwd(char* buf, size_t size);

#endif /* _MYST_CWD_H */
