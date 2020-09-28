#include <stdio.h>

__attribute__((__weak__))
int __vfprintf_chk(FILE* fp, int flag, const char* format, va_list ap)
{
    return vfprintf(fp, format, ap);
}
