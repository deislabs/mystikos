#include <libos/assert.h>
#include <libos/crash.h>
#include <libos/strings.h>

void __libos_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func)
{
    libos_eprintf(
        "Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
    libos_crash();
}
