#include <myst/printf.h>
#include <stdio.h>

int myst_eprintf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vfprintf(stderr, format, ap);
    va_end(ap);

    return n;
}
