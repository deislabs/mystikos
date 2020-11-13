// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <libos/crash.h>
#include <libos/eraise.h>
#include <libos/panic.h>
#include <libos/printf.h>
#include <libos/strings.h>
#include <libos/tcall.h>

int libos_console_printf(int fd, const char* format, ...)
{
    char buf[1024];
    va_list ap;
    int count;

    va_start(ap, format);
    count = vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    if (count < 0 || (size_t)count >= sizeof(buf))
        return -EINVAL;

    return (int)libos_tcall_write_console(fd, buf, (size_t)count);
}

int libos_console_vprintf(int fd, const char* format, va_list ap)
{
    char buf[1024];
    int count;

    count = vsnprintf(buf, sizeof(buf), format, ap);

    if (count < 0 || (size_t)count >= sizeof(buf))
        return -EINVAL;

    return (int)libos_tcall_write_console(fd, buf, (size_t)count);
}

int libos_veprintf(const char* format, va_list ap)
{
    return libos_console_vprintf(STDERR_FILENO, format, ap);
}

int libos_eprintf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = libos_console_vprintf(STDERR_FILENO, format, ap);
    va_end(ap);

    return n;
}
