#ifndef _POSIX_SPINLOCK_H
#define _POSIX_SPINLOCK_H

#include <stdint.h>

#define POSIX_SPINLOCK_INITIALIZER 0

typedef volatile uint32_t posix_spinlock_t;

void posix_spin_lock(posix_spinlock_t* lock);

void posix_spin_unlock(posix_spinlock_t* lock);

#endif /* _POSIX_SPINLOCK_H */
