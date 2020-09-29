#include <stdarg.h>

#include <libos/backtrace.h>
#include <libos/crash.h>
#include <libos/panic.h>
#include <libos/printf.h>

void __libos_panic(
    const char* file,
    size_t line,
    const char* func,
    const char* format,
    ...)
{
    va_list ap;
    void* buf[16];

    size_t n = libos_backtrace(buf, LIBOS_COUNTOF(buf));

    libos_console_printf(
        STDERR_FILENO, "*** kernel panic: %s(%zu): %s(): ", file, line, func);

    va_start(ap, format);
    libos_console_vprintf(STDERR_FILENO, format, ap);
    va_end(ap);

    libos_console_printf(STDERR_FILENO, "\n");

    libos_dump_backtrace(buf, n);

    libos_crash();

    for (;;)
        ;
}
