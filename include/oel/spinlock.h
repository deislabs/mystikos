#ifndef _OEL_SPINLOCK_H
#define _OEL_SPINLOCK_H

#include "types.h"

#define OEL_SPINLOCK_INITIALIZER 0

typedef volatile uint32_t oel_spinlock_t;

int oel_spin_init(oel_spinlock_t* spinlock);

int oel_spin_lock(oel_spinlock_t* spinlock);

int oel_spin_unlock(oel_spinlock_t* spinlock);

int oel_spin_destroy(oel_spinlock_t* spinlock);

#endif /* _OEL_SPINLOCK_H */
