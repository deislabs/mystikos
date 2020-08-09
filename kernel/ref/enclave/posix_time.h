#ifndef _POSIX_TIME_H
#define _POSIX_TIME_H

#include <time.h>
#include <stdint.h>
#include "posix_ocalls.h"

int posix_nanosleep(const struct timespec* req, struct timespec* rem);

int posix_clock_gettime(clockid_t clk_id, struct timespec* tp);

#endif /* _POSIX_TIME_H */
