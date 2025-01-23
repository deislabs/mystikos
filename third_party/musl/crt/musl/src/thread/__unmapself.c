#include <stddef.h>
#include "syscall.h"

void __unmapself(void *base, size_t size)
{
        const long SYS_myst_unmap_on_exit = 2013;
        __syscall2(SYS_myst_unmap_on_exit, base, size);
        __syscall0(SYS_exit);
}
