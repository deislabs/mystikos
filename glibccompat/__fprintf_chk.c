#include <stdarg.h>
#include <stdio.h>

int __fprintf_chk(FILE* stream, int flag, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vfprintf(stream, format, ap);
    va_end(ap);

    return r;
}
