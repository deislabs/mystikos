#include <stdarg.h>
#include <stdio.h>

int __fprintf_chk(FILE* stream, int flag, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int ret = vfprintf(stream, format, ap);
    va_end(ap);
    return ret;
}

int __sprintf_chk(char* s, int flag, size_t slen, const char* format, ...)
{
    va_list ap;
    if (slen == 0)
    {
        abort();
    }
    va_start(ap, format);
    int ret = vsprintf(s, format, ap);
    va_end(ap);
    return ret;
}

int __snprintf_chk(
    char* s,
    size_t maxlen,
    int flag,
    size_t slen,
    const char* format,
    ...)
{
    va_list ap;
    if (slen < maxlen)
    {
        abort();
    }
    va_start(ap, format);
    int ret = vsnprintf(s, maxlen, format, ap);
    va_end(ap);
    return ret;
}

int __vsnprintf_chk(
    char* s,
    size_t maxlen,
    int flag,
    size_t slen,
    const char* format,
    va_list ap)
{
    if (slen < maxlen)
    {
        abort();
    }
    return vsnprintf(s, maxlen, format, ap);
}

int __vsprintf_chk(
    char* s,
    int flag,
    size_t slen,
    const char* format,
    va_list ap)
{
    if (slen == 0)
    {
        abort();
    }
    return vsprintf(s, format, ap);
}

int* ___errno_location(void)
{
    return 0;
}
