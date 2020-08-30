#include <libos/strings.h>

void __stack_chk_fail(void)
{
    libos_panic("__stack_chk_fail()");
}
