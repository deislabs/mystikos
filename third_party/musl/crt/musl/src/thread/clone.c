#include <errno.h>
#include "pthread_impl.h"

weak
int __clone(int (*func)(void *), void *stack, int flags, void *arg, ...)
{
	return -ENOSYS;
}
