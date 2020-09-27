#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void error(int status, int errnum, const char* format, ...)
{
    va_list ap;

    fflush(stdout);
    va_start(ap, format);
    vfprintf(stderr, format, ap);

    if (errnum)
        fprintf(stderr, ": %s\n", strerror(errnum));

    va_end(ap);

    if (status)
        exit(status);
}
