#include <myst/panic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void __myst_panic(
    const char* file,
    size_t line,
    const char* func,
    const char* format,
    ...)
{
    va_list ap;
    void* buf[16];

    fprintf(stderr, "*** crt panic: %s(%zu): %s(): ", file, line, func);

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n");

    abort();
}
