#define _BSD_SOURCE
#include <unistd.h>
#include "syscall.h"
#include <stdarg.h>
#include <errno.h>

#undef syscall

long syscall(long n, ...)
{
	va_list ap;
	syscall_arg_t a,b,c,d,e,f;
	va_start(ap, n);
	a=va_arg(ap, syscall_arg_t);
	b=va_arg(ap, syscall_arg_t);
	c=va_arg(ap, syscall_arg_t);
	d=va_arg(ap, syscall_arg_t);
	e=va_arg(ap, syscall_arg_t);
	f=va_arg(ap, syscall_arg_t);
	va_end(ap);
	return __syscall_ret(__syscall(n,a,b,c,d,e,f));
}

__attribute__((__weak__))
long myst_syscall(long n, long params[6])
{
    (void)n;
    (void)params;
    return EINVAL;
}

long myst_syscall_variadic(long n, ...)
{
    va_list ap;
    long params[6];

    va_start(ap, n);
    params[0] = va_arg(ap, long);
    params[1] = va_arg(ap, long);
    params[2] = va_arg(ap, long);
    params[3] = va_arg(ap, long);
    params[4] = va_arg(ap, long);
    params[5] = va_arg(ap, long);
    va_end(ap);

    return myst_syscall(n, params);
}
