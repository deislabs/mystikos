#include <stdlib.h>
#include "syscall.h"

_Noreturn void do_crt__Exit(int ec)
{
	__syscall(SYS_exit_group, ec);
	for (;;) __syscall(SYS_exit, ec);
}

_Noreturn weak_alias(do_crt__Exit, _Exit);
