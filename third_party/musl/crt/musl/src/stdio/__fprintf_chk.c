#include <stdio.h>
#include <stdarg.h>

extern int __vfprintf_chk(
    FILE *stream,
    int flag,
    const char *format,
    va_list ap);

__attribute__((__weak__))
int __fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
    int ret;
    va_list ap;

    (void)flag;

    va_start(ap, format);
    ret = __vfprintf_chk(stream, flag, format, ap);
    va_end(ap);

    return ret;
}
