// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdarg.h>

#include <myst/backtrace.h>
#include <myst/crash.h>
#include <myst/panic.h>
#include <myst/printf.h>

void __myst_panic(
    const char* file,
    size_t line,
    const char* func,
    const char* format,
    ...)
{
    va_list ap;
    void* buf[16];

    size_t n = myst_backtrace(buf, MYST_COUNTOF(buf));

    myst_console_printf(
        STDERR_FILENO, "*** kernel panic: %s(%zu): %s(): ", file, line, func);

    va_start(ap, format);
    myst_console_vprintf(STDERR_FILENO, format, ap);
    va_end(ap);

    myst_console_printf(STDERR_FILENO, "\n");

    myst_dump_backtrace(buf, n);

    myst_crash();

    for (;;)
        ;
}
