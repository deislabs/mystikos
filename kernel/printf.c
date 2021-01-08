// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <myst/crash.h>
#include <myst/eraise.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/tcall.h>

int myst_console_printf(int fd, const char* format, ...)
{
    char buf[1024];
    va_list ap;
    int count;

    va_start(ap, format);
    count = vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    if (count < 0 || (size_t)count >= sizeof(buf))
        return -EINVAL;

    return (int)myst_tcall_write_console(fd, buf, (size_t)count);
}

int myst_console_vprintf(int fd, const char* format, va_list ap)
{
    char buf[1024];
    int count;

    count = vsnprintf(buf, sizeof(buf), format, ap);

    if (count < 0 || (size_t)count >= sizeof(buf))
        return -EINVAL;

    return (int)myst_tcall_write_console(fd, buf, (size_t)count);
}

int myst_veprintf(const char* format, va_list ap)
{
    return myst_console_vprintf(STDERR_FILENO, format, ap);
}

int myst_eprintf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = myst_console_vprintf(STDERR_FILENO, format, ap);
    va_end(ap);

    return n;
}
