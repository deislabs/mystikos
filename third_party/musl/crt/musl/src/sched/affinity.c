#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include "pthread_impl.h"
#include "syscall.h"

int sched_setaffinity(pid_t tid, size_t size, const cpu_set_t *set)
{
	return syscall(SYS_sched_setaffinity, tid, size, set);
}

int pthread_setaffinity_np(pthread_t td, size_t size, const cpu_set_t *set)
{
	return -__syscall(SYS_sched_setaffinity, td->tid, size, set);
}

static int do_getaffinity(pid_t tid, size_t size, cpu_set_t *set)
{
	long ret = __syscall(SYS_sched_getaffinity, tid, size, set);
	if (ret < 0) return ret;
	if (ret < size) memset((char *)set+ret, 0, size-ret);
	return 0;
}

int sched_getaffinity(pid_t tid, size_t size, cpu_set_t *set)
{
	return __syscall_ret(do_getaffinity(tid, size, set));
}

int pthread_getaffinity_np(pthread_t td, size_t size, cpu_set_t *set)
{
	return -do_getaffinity(td->tid, size, set);
}

int pthread_attr_setaffinity_np(pthread_attr_t *a,
         size_t cpusetsize, const cpu_set_t *cpuset)
{
	if ((!cpuset) || (cpusetsize==0)) 
	{
		if(a->_a_cpuset) free((void*)(a->_a_cpuset));
		a->_a_cpuset = 0;
		a->_a_cpusetsize = 0;
	}
	else
	{
		if(cpusetsize > a->_a_cpusetsize)
		{
			void* attr_cpuset;
			if(!a->_a_cpuset)
				attr_cpuset = malloc(cpusetsize);
			else 
				attr_cpuset = realloc((void*)(a->_a_cpuset), cpusetsize);
			if (!attr_cpuset)
				return ENOMEM;
			else
				a->_a_cpuset = (unsigned long)attr_cpuset;
		}
		memcpy((void*)(a->_a_cpuset), cpuset, cpusetsize);
		a->_a_cpusetsize = cpusetsize;
	}
	return 0;
}

int pthread_attr_getaffinity_np(pthread_attr_t *a,
         size_t cpusetsize, cpu_set_t *cpuset)
{
	if ((!cpuset) || (cpusetsize==0)) 
	{
		return EINVAL;
	}
	else if (cpusetsize < a->_a_cpusetsize)
	{
		return EINVAL;
	}
	memset(cpuset, 0, cpusetsize);
	if (a->_a_cpuset)
		memcpy(cpuset, (void*)a->_a_cpuset, a->_a_cpusetsize );
	return 0;
}