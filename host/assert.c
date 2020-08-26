#include <libos/assert.h>
#include <stdlib.h>
#include <stdio.h>

void __libos_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func)
{
    fprintf(stderr,
        "Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
    abort();
}
