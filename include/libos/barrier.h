#ifndef _LIBOS_BARRIER_H
#define _LIBOS_BARRIER_H

#include <libos/types.h>

#define libos_barrier() __asm__ volatile("" : : : "memory")

#endif /* _LIBOS_BARRIER_H */
