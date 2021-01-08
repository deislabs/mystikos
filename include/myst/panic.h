// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PANIC_H
#define _MYST_PANIC_H

#include <myst/defs.h>
#include <myst/types.h>

MYST_PRINTF_FORMAT(4, 5)
MYST_NORETURN void __myst_panic(
    const char* file,
    size_t line,
    const char* func,
    const char* format,
    ...);

#define myst_panic(format, ...) \
    __myst_panic(__FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)

#endif /* _MYST_PANIC_H */
