// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CLOCK_H
#define _MYST_CLOCK_H

#define NANO_IN_SECOND 1000000000
#define MICRO_IN_SECOND 1000000

struct clock_ctrl
{
    long realtime0;
    long monotime0;
    volatile long now;
    unsigned long interval;
    // Using long to make the size of this struct a multiplier of 8 bytes
    volatile long done;
};

_Static_assert(
    sizeof(struct clock_ctrl) == 40,
    "Size of clock_ctrl should be multiplier of 8 bytes");

int myst_setup_clock(struct clock_ctrl*);

#endif /* _MYST_CLOCK_H */
