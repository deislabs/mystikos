#include <stdarg.h>
#include <stdio.h>

int __printf_chk(int flag, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vprintf(format, ap);
    va_end(ap);

    return r;
}
