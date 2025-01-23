#include "pthread_impl.h"

int __pthread_mutex_lock(pthread_mutex_t *m)
{
	if ((_m_get_type(m)&15) == PTHREAD_MUTEX_NORMAL
	    && !a_cas(&m->_m_lock, 0, EBUSY))
		return 0;

	return __pthread_mutex_timedlock(m, 0);
}

weak_alias(__pthread_mutex_lock, pthread_mutex_lock);
