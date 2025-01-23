#include <stdio.h>
#include <assert.h>

__attribute__((__weak__))
int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap)
{
    assert(stream);
    assert(format);
    (void)flag;
    return vfprintf(stream, format, ap);
}
