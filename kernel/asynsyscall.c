#include <myst/asyncsyscall.h>
#include <myst/tcall.h>

long myst_interrupt_async_syscall(int fd)
{
    return myst_tcall_interrupt_async_syscall(fd);
}
