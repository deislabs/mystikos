#define _BSD_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include "syscall.h"

ssize_t pwritev2(
        int fd,
        const struct iovec *iov,
        int count,
        off_t offset,
        int flags)
{
	return syscall_cp(SYS_pwritev2, fd, iov, count, offset, flags);
}

weak_alias(pwritev2, pwritev64v2);
