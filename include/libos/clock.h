#ifndef _LIBOS_CLOCK_H
#define _LIBOS_CLOCK_H

#define NANO_IN_SECOND 1000000000

struct clock_ctrl
{
    unsigned long realtime0;
    unsigned long monotime0;
    volatile unsigned long now;
    unsigned long interval;
    volatile int done;
};

int libos_setup_clock(struct clock_ctrl*);

#endif /* _LIBOS_CLOCK_H */
