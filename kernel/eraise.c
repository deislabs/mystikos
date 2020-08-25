#include <libos/eraise.h>
#include <libos/errno.h>
#include <stdio.h>
#include <string.h>
#include <libos/trace.h>
#include <libos/deprecated.h>
#include <libos/strings.h>

void libos_eraise(
    const char* file,
    uint32_t line,
    const char* func,
    int errnum)
{
    if (libos_get_trace())
    {
        if (errnum < 0)
            errnum = -errnum;

        libos_eprintf("ERAISE: %s(%u): %s: errno=%d: %s\n",
            file, line, func, errnum, libos_error_name(errnum));
    }
}
