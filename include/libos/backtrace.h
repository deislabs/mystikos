// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_BACKTRACE_H
#define _LIBOS_BACKTRACE_H

#include <stddef.h>

size_t libos_backtrace(void** buffer, size_t size);

void libos_dump_backtrace(void** buffer, size_t size);

#endif /* _LIBOS_BACKTRACE_H */
