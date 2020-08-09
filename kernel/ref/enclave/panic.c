#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdio.h>
#include "posix_panic.h"
#include "posix_io.h"

void posix_panic(
    const char* file,
    unsigned int line,
    const char* func,
    const char* msg)
{
    char buf[1024];

    oe_snprintf(buf, sizeof(buf),
        "posix_panic: %s(%u): %s(): %s\n", file, line, func, msg);

    posix_puts(buf);
    oe_abort();
}
