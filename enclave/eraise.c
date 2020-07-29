#include "eraise.h"
#include <stdio.h>
#include <string.h>

void oel_eraise(
    const char* file,
    uint32_t line,
    const char* func,
    int errnum)
{
    if (errnum < 0)
        errnum = -errnum;

    fprintf(stderr, "ERAISE: %s(%u): %s: errno=%d: %s\n",
        file, line, func, errnum, strerror(errnum));
}
