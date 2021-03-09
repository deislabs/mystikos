// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TIMEVAL_H
#define _MYST_TIMEVAL_H

#include <stdint.h>
#include <sys/time.h>

/* values of tv_sec and tv_usec that produce UINT64_MAX */
#define MYST_TIMEVAL_MAX_SEC ((uint64_t)18446744073709)
#define MYST_TIMEVAL_MAX_USEC ((uint64_t)551615)

/* convert timeval struct to uint64_t usec (-ERANGE on overflow) */
int myst_timeval_to_uint64(const struct timeval* tv, uint64_t* result);

/* convert uint64_t usec to a timeval struct */
int myst_uint64_to_timeval(uint64_t x, struct timeval* tv);

#endif /* _MYST_TIMEVAL_H */
