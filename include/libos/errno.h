// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_ERRNO_H
#define _LIBOS_ERRNO_H

#include <errno.h>

const char* libos_error_name(long errnum);

#endif /* _LIBOS_ERRNO_H */
