#include <unistd.h>
#include "syscall.h"

ssize_t read(int fd, void *buf, size_t count)
{
	return syscall_cp(SYS_read, fd, buf, count);
}
weak_alias(read, __read_nocancel);
