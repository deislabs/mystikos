#include "pthread_impl.h"
#include <threads.h>

int mtx_init(mtx_t *m, int type)
{
	*m = (mtx_t){0};

        if ((type & mtx_recursive))
            _m_set_type((pthread_mutex_t*)m, PTHREAD_MUTEX_RECURSIVE);
        else
            _m_set_type((pthread_mutex_t*)m, PTHREAD_MUTEX_NORMAL);

	return thrd_success;
}
