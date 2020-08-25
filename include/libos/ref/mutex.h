#ifndef _LIBOS_MUTEX_H
#define _LIBOS_MUTEX_H

#include <libos/types.h>

#define LIBOS_MUTEX_INITIALIZER 0

typedef struct libos_mutex
{
    uint64_t __impl[4];
}
libos_mutex_t;

int libos_mutex_init(libos_mutex_t* mutex);

int libos_mutex_lock(libos_mutex_t* mutex);

int libos_mutex_unlock(libos_mutex_t* mutex);

int libos_mutex_destroy(libos_mutex_t* mutex);

#endif /* _LIBOS_MUTEX_H */
