// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SHM_H
#define _MYST_SHM_H

#include <myst/clock.h>

/* Note: members of this struct are copied by value into the enclave */
struct myst_shm
{
    /* clock related shared fields */
    struct clock_ctrl* clock;
};

int shm_create_clock(struct myst_shm* shm, unsigned long clock_tick);
void shm_free_clock(struct myst_shm* shm);

#endif /* _MYST_SHM_H */