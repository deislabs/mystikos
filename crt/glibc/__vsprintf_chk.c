#include <stdarg.h>
#include <stdio.h>

int vsprintf_chk(char* s, int flag, size_t slen, const char* format, va_list ap)
{
    return vsprintf(s, format, ap);
}
