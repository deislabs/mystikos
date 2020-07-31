// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_CWD_H
#define _LIBOS_CWD_H

#include <libos/types.h>

int libos_setcwd(const char* cwd);

int libos_getcwd(libos_path_t* cwd);

#endif /* _LIBOS_CWD_H */
