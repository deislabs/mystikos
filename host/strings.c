#include <libos/strings.h>
#include <stdio.h>
#include <string.h>

char* libos_strdup(const char* s)
{
    return strdup(s);
}

int libos_eprintf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vfprintf(stderr, format, ap);
    va_end(ap);

    return n;
}

int libos_printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vfprintf(stdout, format, ap);
    va_end(ap);

    return n;
}
