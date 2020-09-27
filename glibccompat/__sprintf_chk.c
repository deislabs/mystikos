#include <stdarg.h>
#include <stdio.h>

int __sprintf_chk(char* str, int flag, size_t strlen, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vsprintf(str, format, ap);
    va_end(ap);

    return r;
}
