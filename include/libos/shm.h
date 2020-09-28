#ifndef _LIBOS_SHM_H
#define _LIBOS_SHM_H

#include <libos/clock.h>

/* Note: members of this struct are copied by value into the enclave */
struct libos_shm
{
    /* clock related shared fields */
    struct clock_ctrl* clock;
};

int shm_create_clock(struct libos_shm* shm, unsigned long clock_tick);
void shm_free_clock(struct libos_shm* shm);

#endif /* _LIBOS_SHM_H */