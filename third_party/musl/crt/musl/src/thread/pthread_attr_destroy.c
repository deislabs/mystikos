#include "pthread_impl.h"

int pthread_attr_destroy(pthread_attr_t *a)
{
	if(a->_a_cpuset) free((void*)(a->_a_cpuset));
	return 0;
}