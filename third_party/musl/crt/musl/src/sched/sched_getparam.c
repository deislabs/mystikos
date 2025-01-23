#include <sched.h>
#include <errno.h>
#include "syscall.h"

int do_sched_getparam(pid_t pid, struct sched_param *param)
{
	return __syscall_ret(-ENOSYS);
}

_Noreturn weak_alias(do_sched_getparam, sched_getparam);
