#include <libos/deprecated.h>
#include <libos/eraise.h>
#include <libos/errno.h>
#include <libos/strings.h>
#include <libos/trace.h>
#include <stdio.h>
#include <string.h>

void libos_eraise(const char* file, uint32_t line, const char* func, int errnum)
{
    if (libos_get_trace())
    {
        if (errnum < 0)
            errnum = -errnum;

        libos_eprintf(
            "ERAISE: %s(%u): %s: errno=%d: %s\n",
            file,
            line,
            func,
            errnum,
            libos_error_name(errnum));
    }
}
