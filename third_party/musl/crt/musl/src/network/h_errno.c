#include <netdb.h>

#undef __h_errno
int __h_errno;
 
int *__h_errno_location(void)
{
	return &__h_errno;
}