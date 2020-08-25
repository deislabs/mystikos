#ifndef _LIBOS_SPINLOCK_H
#define _LIBOS_SPINLOCK_H

#include <libos/types.h>
#include <libos/defs.h>

#define LIBOS_SPINLOCK_INITIALIZER 0

typedef volatile uint32_t libos_spinlock_t;

void libos_spin_lock(libos_spinlock_t* spinlock);

void libos_spin_unlock(libos_spinlock_t* spinlock);

typedef struct libos_recursive_spinlock
{
    libos_spinlock_t owner_lock;
    size_t count;
    long owner;
    libos_spinlock_t lock;
}
libos_recursive_spinlock_t;

void libos_recursive_spin_lock(libos_recursive_spinlock_t* s, long thread);

void libos_recursive_spin_unlock(libos_recursive_spinlock_t* s, long thread);

#endif /* _LIBOS_SPINLOCK_H */
