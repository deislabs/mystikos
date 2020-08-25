#include "common.h"
#include <libos/syscall.h>
#include <libos/eraise.h>

int libos_chdir(const char* path)
{
    return (int)libos_syscall_ret(libos_syscall_chdir(path));
}

char* libos_getcwd(char* buf, size_t size)
{
    return (char*)libos_syscall_ret(libos_syscall_getcwd(buf, size));
}
