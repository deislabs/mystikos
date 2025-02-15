#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include "syscall.h"

int fcntl(int fd, int cmd, ...)
{
	unsigned long arg;
	va_list ap;
	va_start(ap, cmd);
	arg = va_arg(ap, unsigned long);
	va_end(ap);
	if (cmd == F_SETFL) arg |= O_LARGEFILE;
	if (cmd == F_SETLKW) return syscall_cp(SYS_fcntl, fd, cmd, (void *)arg);
	if (cmd == F_GETOWN) {
		struct f_owner_ex ex;
		int ret = __syscall(SYS_fcntl, fd, F_GETOWN_EX, &ex);
		if (ret == -EINVAL) return __syscall(SYS_fcntl, fd, cmd, (void *)arg);
		if (ret) return __syscall_ret(ret);
		return ex.type == F_OWNER_PGRP ? -ex.pid : ex.pid;
	}
	if (cmd == F_DUPFD_CLOEXEC) {
		int ret = __syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, arg);
		if (ret != -EINVAL) {
			if (ret >= 0)
				__syscall(SYS_fcntl, ret, F_SETFD, FD_CLOEXEC);
			return __syscall_ret(ret);
		}
		ret = __syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 0);
		if (ret != -EINVAL) {
			if (ret >= 0) __syscall(SYS_close, ret);
			return __syscall_ret(-EINVAL);
		}
		ret = __syscall(SYS_fcntl, fd, F_DUPFD, arg);
		if (ret >= 0) __syscall(SYS_fcntl, ret, F_SETFD, FD_CLOEXEC);
		return __syscall_ret(ret);
	}
	switch (cmd) {
	case F_SETLK:
	case F_GETLK:
	case F_GETOWN_EX:
	case F_SETOWN_EX:
		return syscall(SYS_fcntl, fd, cmd, (void *)arg);
	default:
		return syscall(SYS_fcntl, fd, cmd, arg);
	}
}

weak_alias(fcntl, fcntl64);