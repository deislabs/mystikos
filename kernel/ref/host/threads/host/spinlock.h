#ifndef _SPINLOCK_H
#define _SPINLOCK_H

#include <stdint.h>

#define SPINLOCK_INITIALIZER 0

typedef volatile uint32_t spinlock_t;

void spin_lock(spinlock_t* lock);

void spin_unlock(spinlock_t* lock);

#endif /* _SPINLOCK_H */
