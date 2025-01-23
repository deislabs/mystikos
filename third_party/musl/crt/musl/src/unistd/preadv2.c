#define _BSD_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include "syscall.h"

ssize_t preadv2(
        int fd,
        const struct iovec *iov,
        int count,
        off_t offset,
        int flags)
{
	return syscall_cp(SYS_preadv2, fd, iov, count, offset, flags);
}

weak_alias(preadv2, preadv64v2);
