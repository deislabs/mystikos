#include <stdio.h>
#include <stdlib.h>

#include <libos/buf.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/strings.h>
#include <libos/syscall.h>
#include <libos/trace.h>

int libos_getdents64(int fd, struct dirent* dirp, size_t count)
{
    return (int)libos_syscall_ret(libos_syscall_getdents64(fd, dirp, count));
}
