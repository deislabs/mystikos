#ifndef _OEL_MUTEX_H
#define _OEL_MUTEX_H

#include "types.h"

#define OEL_MUTEX_INITIALIZER 0

typedef struct _oel_mutex
{
    uint64_t __impl[4];
}
oel_mutex_t;

int oel_mutex_init(oel_mutex_t* mutex);

int oel_mutex_lock(oel_mutex_t* mutex);

int oel_mutex_unlock(oel_mutex_t* mutex);

int oel_mutex_destroy(oel_mutex_t* mutex);

#endif /* _OEL_MUTEX_H */
