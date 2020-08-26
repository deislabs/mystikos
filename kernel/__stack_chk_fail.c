#include <libos/strings.h>
#include <libos/crash.h>

void __stack_chk_fail(void)
{
    libos_eprintf("__stack_chk_fail(): panic\n");
    libos_crash();
}
