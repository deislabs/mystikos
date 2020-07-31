#ifndef _LIBOS_SPINLOCK_H
#define _LIBOS_SPINLOCK_H

#include <libos/types.h>

#define LIBOS_SPINLOCK_INITIALIZER 0

typedef volatile uint32_t libos_spinlock_t;

int libos_spin_init(libos_spinlock_t* spinlock);

int libos_spin_lock(libos_spinlock_t* spinlock);

int libos_spin_unlock(libos_spinlock_t* spinlock);

int libos_spin_destroy(libos_spinlock_t* spinlock);

#endif /* _LIBOS_SPINLOCK_H */
