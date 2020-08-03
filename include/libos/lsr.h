// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_LSR_H
#define _LIBOS_LSR_H

#include <libos/types.h>
#include <libos/strarr.h>

int libos_lsr(const char* root, libos_strarr_t* paths);

#endif /* _LIBOS_LSR_H */
