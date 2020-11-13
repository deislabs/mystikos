// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_PRINTF_H
#define _LIBOS_PRINTF_H

#include <libos/defs.h>
#include <libos/types.h>
#include <stdarg.h>
#include <unistd.h>

LIBOS_PRINTF_FORMAT(2, 3)
int libos_console_printf(int fd, const char* format, ...);

int libos_console_vprintf(int fd, const char* format, va_list ap);

int libos_veprintf(const char* format, va_list ap);

LIBOS_PRINTF_FORMAT(1, 2)
int libos_eprintf(const char* format, ...);

#endif /* _LIBOS_PRINTF_H */
