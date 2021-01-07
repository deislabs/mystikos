// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PRINTF_H
#define _MYST_PRINTF_H

#include <myst/defs.h>
#include <myst/types.h>
#include <stdarg.h>
#include <unistd.h>

MYST_PRINTF_FORMAT(2, 3)
int myst_console_printf(int fd, const char* format, ...);

int myst_console_vprintf(int fd, const char* format, va_list ap);

int myst_veprintf(const char* format, va_list ap);

MYST_PRINTF_FORMAT(1, 2)
int myst_eprintf(const char* format, ...);

#endif /* _MYST_PRINTF_H */
