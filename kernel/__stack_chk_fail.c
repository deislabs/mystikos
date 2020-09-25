#include <libos/panic.h>
#include <libos/strings.h>
#include <libos/thread.h>

void __stack_chk_fail(void)
{
    libos_panic("__stack_chk_fail()");
}
