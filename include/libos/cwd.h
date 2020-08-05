// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_CWD_H
#define _LIBOS_CWD_H

#include <libos/types.h>

int libos_chdir(const char* path);

char* libos_getcwd(char* buf, size_t size);

#endif /* _LIBOS_CWD_H */
